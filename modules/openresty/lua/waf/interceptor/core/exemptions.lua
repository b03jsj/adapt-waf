local cjson = require("cjson.safe")
local config = require("waf.interceptor.core.config")

local _M = {}

local state = {
    generation = 0,
    sha256 = "-",
    exact_index = {},
    detector_field_index = {},
    pattern_state_index = {},
    rule_count = 0,
    pattern_state_count = 0,
    last_error = nil,
    last_apply_ts = nil
}

local function get_dict()
    local dict_name = config.get().exemptions.dict_name
    return ngx.shared[dict_name]
end

local function safe(value)
    if not value or value == "" then
        return "-"
    end
    return tostring(value)
end

local function field_selector(surface, field_name, json_path)
    if surface == "json" and json_path and json_path ~= "" and json_path ~= "-" then
        return json_path
    end
    if field_name and field_name ~= "" then
        return field_name
    end
    return "-"
end

local function exact_key(rule)
    return table.concat({
        safe(rule.method),
        safe(rule.route_key),
        safe(rule.content_type),
        safe(rule.surface),
        safe(field_selector(rule.surface, rule.field_name, rule.json_path)),
        safe(rule.detector),
        safe(rule.signature)
    }, "|")
end

local function detector_field_key(rule)
    return table.concat({
        safe(rule.method),
        safe(rule.route_key),
        safe(rule.content_type),
        safe(rule.surface),
        safe(field_selector(rule.surface, rule.field_name, rule.json_path)),
        safe(rule.detector)
    }, "|")
end

local function to_hex(binary)
    return (binary:gsub(".", function(ch)
        return string.format("%02x", string.byte(ch))
    end))
end

local function sha256_hex(value)
    return to_hex(ngx.sha256_bin(value))
end

local function is_detector_field_scope_allowed(rule)
    if safe(rule.match_scope) ~= "detector_field" then
        return true
    end
    local detector = safe(rule.detector)
    return detector == "libinjection_sqli" or detector == "libinjection_xss"
end

local function build_indexes(rules)
    local exact = {}
    local detector_field = {}
    local count = 0

    for _, rule in ipairs(rules or {}) do
        if rule.enabled ~= false then
            if not is_detector_field_scope_allowed(rule) then
                return nil, nil, nil, "detector_scope_not_allowed:" .. safe(rule.detector)
            end

            local scope = safe(rule.match_scope)
            if scope == "signature_exact" then
                local key = exact_key(rule)
                if exact[key] then
                    return nil, nil, nil, "duplicate_exact_key:" .. key
                end
                exact[key] = rule
                count = count + 1
            elseif scope == "detector_field" then
                local key = detector_field_key(rule)
                if detector_field[key] then
                    return nil, nil, nil, "duplicate_detector_field_key:" .. key
                end
                detector_field[key] = rule
                count = count + 1
            else
                return nil, nil, nil, "invalid_match_scope:" .. scope
            end
        end
    end

    return exact, detector_field, count, nil
end

local function normalize_pattern_state_key(value)
    local text = safe(value)
    return string.lower(text)
end

local function build_pattern_state_index(payload)
    local index = {}
    local count = 0
    local source = payload.pattern_state_index
    if type(source) ~= "table" then
        return index, count, nil
    end

    for state_name, keys in pairs(source) do
        local normalized_state = normalize_pattern_state_key(state_name)
        if normalized_state == "benign_confirmed" or normalized_state == "attack_confirmed" then
            if type(keys) ~= "table" then
                return nil, nil, "invalid_pattern_state_keys:" .. normalized_state
            end
            for _, key in ipairs(keys) do
                local hash = safe(key)
                if hash ~= "-" then
                    if index[hash] and index[hash] ~= normalized_state then
                        return nil, nil, "pattern_state_conflict:" .. hash
                    end
                    if not index[hash] then
                        count = count + 1
                    end
                    index[hash] = normalized_state
                end
            end
        end
    end

    return index, count, nil
end

local function read_file(path)
    local f, open_err = io.open(path, "rb")
    if not f then
        return nil, "open_failed:" .. tostring(open_err)
    end

    local content = f:read("*a")
    f:close()
    if not content or content == "" then
        return nil, "empty_snapshot"
    end
    return content, nil
end

local function apply_snapshot(content, payload, generation, cfg, dict, target_sha256)
    local exact, detector_field, rule_count, build_err = build_indexes(payload.rules)
    if not exact then
        state.last_error = build_err
        dict:set(cfg.status_key, "failed")
        dict:set(cfg.error_key, build_err)
        return false
    end

    local pattern_state_index, pattern_state_count, state_err = build_pattern_state_index(payload)
    if not pattern_state_index then
        state.last_error = state_err
        dict:set(cfg.status_key, "failed")
        dict:set(cfg.error_key, state_err)
        return false
    end

    state.exact_index = exact
    state.detector_field_index = detector_field
    state.pattern_state_index = pattern_state_index
    state.generation = generation
    state.sha256 = target_sha256 or sha256_hex(content)
    state.rule_count = rule_count
    state.pattern_state_count = pattern_state_count
    state.last_error = nil
    state.last_apply_ts = ngx.now()

    dict:set(cfg.current_key, generation)
    dict:set(cfg.status_key, "ok")
    dict:delete(cfg.error_key)
    return true
end

local function bootstrap_from_runtime_file()
    local dict = get_dict()
    if not dict then
        state.last_error = "dict_missing"
        return
    end

    local cfg = config.get().exemptions
    local content, read_err = read_file(cfg.runtime_source)
    if not content then
        -- 首次启动允许无快照，不视为故障。
        if read_err ~= "empty_snapshot" then
            state.last_error = read_err
        end
        return
    end

    local payload, decode_err = cjson.decode(content)
    if not payload then
        state.last_error = "invalid_bootstrap_json:" .. tostring(decode_err)
        return
    end

    if payload.schema_version ~= "exemptions-compiled-v1" then
        state.last_error = "invalid_bootstrap_schema"
        return
    end

    local snapshot_generation = tonumber(payload.generation or 0)
    if snapshot_generation <= 0 then
        state.last_error = "invalid_bootstrap_generation"
        return
    end

    local snapshot_sha = sha256_hex(content)
    local applied = apply_snapshot(content, payload, snapshot_generation, cfg, dict, snapshot_sha)
    if not applied then
        return
    end

    local current_target = tonumber(dict:get(cfg.target_key) or 0)
    if current_target < snapshot_generation then
        dict:set(cfg.target_key, snapshot_generation)
    end
    dict:set(cfg.target_sha256_key, snapshot_sha)
    dict:set(cfg.target_size_key, #content)
end

local function apply_target_generation(premature)
    if premature then
        return
    end

    local dict = get_dict()
    if not dict then
        state.last_error = "dict_missing"
        return
    end

    local cfg = config.get().exemptions
    local target_generation = dict:get(cfg.target_key)
    if not target_generation or target_generation <= state.generation then
        return
    end
    local target_sha256 = dict:get(cfg.target_sha256_key)

    local content, read_err = read_file(cfg.runtime_source)
    if not content then
        state.last_error = read_err
        dict:set(cfg.status_key, "failed")
        dict:set(cfg.error_key, read_err)
        return
    end

    if target_sha256 and target_sha256 ~= "" and target_sha256 ~= "-" then
        local expected_sha = tostring(target_sha256):gsub("^sha256:", "")
        local current_sha = sha256_hex(content)
        if expected_sha ~= current_sha then
            local err = "snapshot_sha256_mismatch"
            state.last_error = err
            dict:set(cfg.status_key, "failed")
            dict:set(cfg.error_key, err)
            return
        end
    end

    local payload, decode_err = cjson.decode(content)
    if not payload then
        local err = "invalid_json:" .. tostring(decode_err)
        state.last_error = err
        dict:set(cfg.status_key, "failed")
        dict:set(cfg.error_key, err)
        return
    end

    if payload.schema_version ~= "exemptions-compiled-v1" then
        local err = "schema_version_invalid"
        state.last_error = err
        dict:set(cfg.status_key, "failed")
        dict:set(cfg.error_key, err)
        return
    end

    if tonumber(payload.generation) ~= tonumber(target_generation) then
        local err = "snapshot_generation_mismatch"
        state.last_error = err
        dict:set(cfg.status_key, "failed")
        dict:set(cfg.error_key, err)
        return
    end

    apply_snapshot(content, payload, target_generation, cfg, dict, target_sha256)
end

local function schedule_worker_timer()
    local interval = config.get().exemptions.worker_apply_interval_seconds
    local ok, err = ngx.timer.every(interval, apply_target_generation)
    if not ok then
        ngx.log(ngx.ERR, "豁免热加载定时器启动失败: ", tostring(err))
    end
end

---初始化豁免热加载机制。
function _M.init_worker()
    bootstrap_from_runtime_file()
    apply_target_generation(false)
    schedule_worker_timer()
end

local function runtime_exact_key(ctx, signals)
    return table.concat({
        safe(ctx.method),
        safe(ctx.route_key),
        safe(ctx.content_type),
        safe(ctx.surface),
        safe(field_selector(ctx.surface, ctx.field_name, ctx.json_path)),
        safe(signals.detector),
        safe(signals.detector_signature)
    }, "|")
end

local function runtime_detector_field_key(ctx, signals)
    return table.concat({
        safe(ctx.method),
        safe(ctx.route_key),
        safe(ctx.content_type),
        safe(ctx.surface),
        safe(field_selector(ctx.surface, ctx.field_name, ctx.json_path)),
        safe(signals.detector)
    }, "|")
end

---按“精确优先 + 显式放宽”执行豁免匹配。
---@return table
function _M.match(ctx, signals)
    local pattern_state = state.pattern_state_index[safe(ctx.pattern_key_hash)] or "unknown"
    local result = {
        applied = false,
        exemption_id = nil,
        match_scope = "",
        match_key = "",
        pattern_state = pattern_state,
        generation = state.generation
    }

    if not signals or not signals.parser_hit then
        return result
    end

    local exact = state.exact_index[runtime_exact_key(ctx, signals)]
    if exact then
        local key = runtime_exact_key(ctx, signals)
        result.applied = true
        result.exemption_id = exact.id or exact.exemption_id or "-"
        result.match_scope = "signature_exact"
        result.match_key = key
        return result
    end

    local detector_field = state.detector_field_index[runtime_detector_field_key(ctx, signals)]
    if detector_field then
        local key = runtime_detector_field_key(ctx, signals)
        result.applied = true
        result.exemption_id = detector_field.id or detector_field.exemption_id or "-"
        result.match_scope = "detector_field"
        result.match_key = key
        return result
    end

    return result
end

---获取当前豁免快照状态。
---@return table
function _M.status()
    return {
        generation = state.generation,
        sha256 = state.sha256,
        rule_count = state.rule_count,
        pattern_state_count = state.pattern_state_count,
        last_error = state.last_error,
        last_apply_ts = state.last_apply_ts
    }
end

return _M
