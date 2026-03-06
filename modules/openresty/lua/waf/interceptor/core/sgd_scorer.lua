local cjson = require("cjson.safe")
local bit = require("bit")
local config = require("waf.interceptor.core.config")

local _M = {}

local state = {
    backend = "lua_ffi",
    sqli = nil,
    xss = nil
}

local VALID_RELEASE_STATES = {
    candidate = true,
    shadow_observe = true,
    stable = true
}

local function to_hex(binary)
    return (binary:gsub(".", function(ch)
        return string.format("%02x", string.byte(ch))
    end))
end

local function sha256_hex(value)
    return to_hex(ngx.sha256_bin(value))
end

local function read_file(path)
    local f, open_err = io.open(path, "rb")
    if not f then
        return nil, "open_failed:" .. tostring(open_err)
    end

    local content = f:read("*a")
    f:close()
    if not content then
        return nil, "read_failed"
    end
    return content, nil
end

local function join_path(dir, file)
    if dir:sub(-1) == "/" then
        return dir .. file
    end
    return dir .. "/" .. file
end

local function resolve_weights_path(manifest_path, manifest)
    if manifest.weights_file and manifest.weights_file ~= "" then
        local base_dir = manifest_path:match("^(.*)/[^/]+$")
        if base_dir then
            return join_path(base_dir, manifest.weights_file)
        end
        return manifest.weights_file
    end
    return nil
end

local function load_model(attack_type, manifest_path)
    local manifest_raw, manifest_err = read_file(manifest_path)
    if not manifest_raw then
        local missing = tostring(manifest_err):find("No such file", 1, true) ~= nil
        return {
            attack_type = attack_type,
            load_state = missing and "cold_start" or "disabled",
            model_state = missing and "cold_start" or "disabled",
            error = manifest_err
        }
    end

    local manifest, decode_err = cjson.decode(manifest_raw)
    if not manifest then
        return {
            attack_type = attack_type,
            load_state = "disabled",
            model_state = "disabled",
            error = "manifest_invalid_json:" .. tostring(decode_err)
        }
    end

    if manifest.format ~= "sgd-linear-v1" then
        return {
            attack_type = attack_type,
            load_state = "disabled",
            model_state = "disabled",
            error = "unsupported_format"
        }
    end

    if manifest.attack_type ~= attack_type then
        return {
            attack_type = attack_type,
            load_state = "disabled",
            model_state = "disabled",
            error = "attack_type_mismatch"
        }
    end

    local release_state = tostring(manifest.model_state or "stable")
    release_state = string.lower(release_state)
    if not VALID_RELEASE_STATES[release_state] then
        return {
            attack_type = attack_type,
            load_state = "disabled",
            model_state = "disabled",
            error = "invalid_model_state"
        }
    end

    local cfg = config.get().model
    local norm_profile = config.get().normalization.active_profile
    if manifest.normalization_profile ~= norm_profile then
        return {
            attack_type = attack_type,
            load_state = "disabled",
            model_state = "disabled",
            error = "normalization_profile_mismatch"
        }
    end

    local hash_dim = tonumber(manifest.hash_dim or 0)
    if hash_dim <= 0 or hash_dim > cfg.max_hash_dim then
        return {
            attack_type = attack_type,
            load_state = "disabled",
            model_state = "disabled",
            error = "invalid_hash_dim"
        }
    end

    local weights_path = resolve_weights_path(manifest_path, manifest)
    if not weights_path then
        return {
            attack_type = attack_type,
            load_state = "disabled",
            model_state = "disabled",
            error = "weights_path_missing"
        }
    end

    local weights_raw, weights_err = read_file(weights_path)
    if not weights_raw then
        local missing = tostring(weights_err):find("No such file", 1, true) ~= nil
        return {
            attack_type = attack_type,
            load_state = missing and "cold_start" or "disabled",
            model_state = missing and "cold_start" or "disabled",
            error = weights_err
        }
    end

    if #weights_raw ~= hash_dim * 4 then
        return {
            attack_type = attack_type,
            load_state = "disabled",
            model_state = "disabled",
            error = "weights_size_mismatch"
        }
    end

    if manifest.weights_sha256 and manifest.weights_sha256 ~= "" then
        local expected = tostring(manifest.weights_sha256):gsub("^sha256:", "")
        local current = sha256_hex(weights_raw)
        if expected ~= current then
            return {
                attack_type = attack_type,
                load_state = "disabled",
                model_state = "disabled",
                error = "weights_sha256_mismatch"
            }
        end
    end

    local ok_ffi, ffi = pcall(require, "ffi")
    if not ok_ffi then
        return {
            attack_type = attack_type,
            load_state = "disabled",
            model_state = "disabled",
            error = "ffi_unavailable"
        }
    end

    local buffer = ffi.new("uint8_t[?]", #weights_raw)
    ffi.copy(buffer, weights_raw, #weights_raw)
    local weights_ptr = ffi.cast("float*", buffer)

    return {
        attack_type = attack_type,
        load_state = "active",
        model_state = release_state,
        backend = "lua_ffi",
        model_version = manifest.model_version or "unknown",
        hash_dim = hash_dim,
        ngram_min = tonumber(manifest.ngram_min or 3),
        ngram_max = tonumber(manifest.ngram_max or 5),
        bias = tonumber(manifest.bias or 0),
        weights_buffer = buffer,
        weights_ptr = weights_ptr
    }
end

local function fnv1a_32(value, start_index, stop_index)
    local hash = 2166136261
    for i = start_index, stop_index do
        hash = bit.bxor(hash, string.byte(value, i))
        hash = bit.tobit(hash * 16777619)
    end
    return bit.band(hash, 0x7fffffff)
end

local function raw_score(model, text)
    local n = #text
    if n <= 0 then
        return model.bias
    end

    local score = model.bias
    local ngram_min = model.ngram_min
    local ngram_max = model.ngram_max

    for gram = ngram_min, ngram_max do
        if n >= gram then
            for start_idx = 1, n - gram + 1 do
                local hash = fnv1a_32(text, start_idx, start_idx + gram - 1)
                local bucket = (hash % model.hash_dim)
                score = score + tonumber(model.weights_ptr[bucket])
            end
        end
    end

    return score
end

local function sigmoid(value)
    if value > 50 then
        return 1.0
    end
    if value < -50 then
        return 0.0
    end
    return 1 / (1 + math.exp(-value))
end

---初始化 worker 级 SGD 模型加载。
function _M.init_worker()
    local cfg = config.get().model
    state.backend = cfg.scorer_backend
    state.sqli = load_model("sqli", cfg.sqli_manifest_path)
    state.xss = load_model("xss", cfg.xss_manifest_path)
end

---对文本执行指定攻击类型的 SGD 评分。
---@param attack_type string
---@param text string
---@return table
function _M.score(attack_type, text)
    local model = (attack_type == "xss") and state.xss or state.sqli
    if not model then
        return {
            backend = state.backend,
            model_state = "disabled",
            model_load_state = "disabled",
            model_version = "none",
            raw = 0,
            score = 0
        }
    end

    if model.load_state ~= "active" then
        return {
            backend = state.backend,
            model_state = model.model_state or model.load_state,
            model_load_state = model.load_state,
            model_version = model.model_version or "none",
            raw = 0,
            score = 0,
            error = model.error
        }
    end

    local raw = raw_score(model, text or "")
    local score = sigmoid(raw)
    return {
        backend = model.backend,
        model_state = model.model_state,
        model_load_state = model.load_state,
        model_version = model.model_version,
        raw = raw,
        score = score
    }
end

---返回当前模型状态。
---@return table
function _M.status()
    local function summarize(model)
        if not model then
            return {
                load_state = "disabled",
                model_state = "disabled",
                model_version = "none"
            }
        end
        return {
            load_state = model.load_state,
            model_state = model.model_state,
            model_version = model.model_version or "none",
            hash_dim = model.hash_dim,
            ngram_min = model.ngram_min,
            ngram_max = model.ngram_max,
            error = model.error
        }
    end

    return {
        backend = state.backend,
        sqli = summarize(state.sqli),
        xss = summarize(state.xss)
    }
end

return _M
