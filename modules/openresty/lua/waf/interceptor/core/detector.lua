local normalization = require("waf.interceptor.core.normalization")
local libinjection_adapter = require("waf.interceptor.core.libinjection_adapter")
local sgd_scorer = require("waf.interceptor.core.sgd_scorer")

local _M = {}

local function build_fingerprint(detector, signature, field_name, value)
    local seed = table.concat({
        detector or "-",
        signature or "-",
        field_name or "-",
        value or "-"
    }, "|")
    return string.sub(ngx.md5(seed), 1, 16)
end

local function iter_fields(ctx)
    local fields = {
        {
            surface = "uri",
            field_name = "__uri__",
            json_path = "-",
            value = ctx.route_key or ""
        }
    }

    if ctx.fields then
        for _, field in ipairs(ctx.fields) do
            fields[#fields + 1] = field
        end
    end

    return fields
end

local function calc_weak_signal(model_sqli_input, model_xss_input)
    local text = (model_sqli_input or "") .. " " .. (model_xss_input or "")
    local score = 0

    if text:find(" or ", 1, true) then
        score = score + 1
    end
    if text:find("--", 1, true) or text:find("/*", 1, true) then
        score = score + 1
    end
    if text:find("<", 1, true) and text:find(">", 1, true) then
        score = score + 1
    end
    if #text > 256 then
        score = score + 1
    end
    if text:find("javascript:", 1, true) then
        score = score + 1
    end

    return score
end

local function apply_match(signals, detector_name, signature_seed, field, views, model_score, model_meta)
    signals.detector = detector_name
    signals.detector_signature = build_fingerprint(detector_name, signature_seed, field.field_name, views.raw_value)
    signals.parser_hit = true
    signals.matched_surface = field.surface
    signals.matched_field_name = field.field_name
    signals.matched_json_path = field.json_path
    signals.matched_value = views.raw_value
    signals.normalized_sqli_value = views.normalized_sqli_value
    signals.normalized_xss_value = views.normalized_xss_value
    signals.model_sqli_input = views.model_sqli_input
    signals.model_xss_input = views.model_xss_input
    signals.model_input_truncated = views.model_input_truncated
    signals.normalization_profile = views.normalization_profile
    signals.invalid_utf8 = views.invalid_utf8
    signals.sgd_score = model_score
    signals.sgd_score_raw = model_meta.raw
    signals.sgd_backend = model_meta.backend
    signals.sgd_model_state = model_meta.model_state
    signals.sgd_model_load_state = model_meta.model_load_state
    signals.model_version = model_meta.model_version
end

---初始化检测器依赖。
function _M.init_worker()
    libinjection_adapter.init()
    sgd_scorer.init_worker()
end

---执行检测插件并返回标准化信号。
---检测顺序：libinjection(SQLi/XSS) -> 弱信号 -> SGD 辅助。
function _M.inspect(ctx)
    local signals = {
        detector = "none",
        detector_signature = "-",
        parser_hit = false,
        weak_signal_score = 0,
        sgd_score = 0,
        sgd_score_raw = 0,
        sgd_backend = "lua_ffi",
        sgd_model_state = "disabled",
        sgd_model_load_state = "disabled",
        model_version = "none",
        matched_surface = "-",
        matched_field_name = "-",
        matched_json_path = "-",
        matched_value = "",
        normalized_sqli_value = "",
        normalized_xss_value = "",
        model_sqli_input = "",
        model_xss_input = "",
        model_input_truncated = false,
        normalization_profile = "norm-v1",
        invalid_utf8 = false,
        libinjection_required = false,
        libinjection_available = false,
        libinjection_backend = "unavailable",
        libinjection_load_error = "",
        detector_unavailable = false
    }

    local lib_status = libinjection_adapter.status()
    signals.libinjection_required = lib_status.require_module == true
    signals.libinjection_available = lib_status.loaded == true
    signals.libinjection_load_error = lib_status.load_error or ""

    local max_weak_score = 0
    local max_sgd = 0
    local chosen_for_non_parser = nil

    for _, field in ipairs(iter_fields(ctx)) do
        local views = normalization.build_views(field.surface, field.value or "")

        local weak_score = calc_weak_signal(views.model_sqli_input, views.model_xss_input)
        if weak_score > max_weak_score then
            max_weak_score = weak_score
        end

        local sqli_model = sgd_scorer.score("sqli", views.model_sqli_input)
        local xss_model = sgd_scorer.score("xss", views.model_xss_input)
        local field_sgd = math.max(sqli_model.score or 0, xss_model.score or 0)

        if field_sgd > max_sgd then
            max_sgd = field_sgd
            chosen_for_non_parser = {
                field = field,
                views = views,
                model = (sqli_model.score >= xss_model.score) and sqli_model or xss_model
            }
        end

        local sqli_hit, sqli_signature, sqli_backend = libinjection_adapter.sqli(views.normalized_sqli_value)
        if sqli_hit then
            apply_match(signals, "libinjection_sqli", sqli_signature, field, views, field_sgd, sqli_model)
            signals.libinjection_backend = sqli_backend
            signals.weak_signal_score = max_weak_score
            return signals
        end

        local xss_hit, xss_signature, xss_backend = libinjection_adapter.xss(views.normalized_xss_value)
        if xss_hit then
            apply_match(signals, "libinjection_xss", xss_signature, field, views, field_sgd, xss_model)
            signals.libinjection_backend = xss_backend
            signals.weak_signal_score = max_weak_score
            return signals
        end

        if signals.libinjection_backend == "unavailable" then
            signals.libinjection_backend = sqli_backend or xss_backend or "unavailable"
        end
    end

    signals.weak_signal_score = max_weak_score
    signals.sgd_score = max_sgd

    if chosen_for_non_parser then
        signals.matched_surface = chosen_for_non_parser.field.surface
        signals.matched_field_name = chosen_for_non_parser.field.field_name
        signals.matched_json_path = chosen_for_non_parser.field.json_path
        signals.matched_value = chosen_for_non_parser.views.raw_value
        signals.normalized_sqli_value = chosen_for_non_parser.views.normalized_sqli_value
        signals.normalized_xss_value = chosen_for_non_parser.views.normalized_xss_value
        signals.model_sqli_input = chosen_for_non_parser.views.model_sqli_input
        signals.model_xss_input = chosen_for_non_parser.views.model_xss_input
        signals.model_input_truncated = chosen_for_non_parser.views.model_input_truncated
        signals.normalization_profile = chosen_for_non_parser.views.normalization_profile
        signals.invalid_utf8 = chosen_for_non_parser.views.invalid_utf8
        signals.sgd_score_raw = chosen_for_non_parser.model.raw or 0
        signals.sgd_backend = chosen_for_non_parser.model.backend or "lua_ffi"
        signals.sgd_model_state = chosen_for_non_parser.model.model_state or "disabled"
        signals.sgd_model_load_state = chosen_for_non_parser.model.model_load_state or "disabled"
        signals.model_version = chosen_for_non_parser.model.model_version or "none"
    end

    if max_weak_score >= 2 then
        signals.detector = "rule_engine"
        signals.detector_signature = build_fingerprint(
                signals.detector,
                "weak_combo",
                signals.matched_field_name,
                signals.matched_value
        )
    end

    if libinjection_adapter.hard_unavailable() then
        signals.detector_unavailable = true
        signals.libinjection_backend = "unavailable"
    end

    return signals
end

---返回检测器依赖状态，用于运维排查。
---@return table
function _M.status()
    return {
        libinjection = libinjection_adapter.status(),
        sgd = sgd_scorer.status()
    }
end

return _M
