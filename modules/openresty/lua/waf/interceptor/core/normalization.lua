local config = require("waf.interceptor.core.config")

local _M = {}

local ENTITY_MAP = {
    ["&lt;"] = "<",
    ["&gt;"] = ">",
    ["&amp;"] = "&",
    ["&quot;"] = "\"",
    ["&#39;"] = "'",
    ["&apos;"] = "'"
}

local function safe_surface(surface)
    if not surface or surface == "" then
        return "query"
    end
    return surface
end

local function decode_url_once(value)
    local ok, decoded = pcall(ngx.unescape_uri, value)
    if ok and decoded then
        return decoded
    end
    return value
end

local function decode_url_by_surface(surface, value, cfg)
    local passes = cfg.url_decode_surfaces[surface] or 0
    passes = math.min(passes, cfg.url_decode_max_passes)
    local current = value

    for _ = 1, passes do
        local decoded = decode_url_once(current)
        if decoded == current then
            break
        end
        current = decoded
    end
    return current
end

local function decode_entity_once(value)
    local current = value:gsub("&#x([0-9a-fA-F]+);", function(hex)
        local code = tonumber(hex, 16)
        if not code or code < 0 or code > 255 then
            return "?"
        end
        return string.char(code)
    end)

    current = current:gsub("&#([0-9]+);", function(dec)
        local code = tonumber(dec, 10)
        if not code or code < 0 or code > 255 then
            return "?"
        end
        return string.char(code)
    end)

    current = current:gsub("&[a-zA-Z]+;", function(entity)
        return ENTITY_MAP[string.lower(entity)] or entity
    end)

    return current
end

local function decode_entity(value, max_passes)
    local current = value
    for _ = 1, max_passes do
        local decoded = decode_entity_once(current)
        if decoded == current then
            break
        end
        current = decoded
    end
    return current
end

local function fold_for_model(value, cfg)
    local lowered = string.lower(value)
    lowered = lowered:gsub("[%s]+", " ")
    if #lowered > cfg.model_feature_max_bytes then
        return lowered:sub(1, cfg.model_feature_max_bytes), true
    end
    return lowered, false
end

local function is_valid_utf8(value)
    if not ngx.re then
        return true
    end
    local ok, matched_or_err, err = pcall(ngx.re.find, value, "^.*$", "u")
    if not ok then
        return false
    end
    if matched_or_err then
        return true
    end
    return err == nil
end

---按照 norm-v1 生成检测与模型视图。
---@param surface string
---@param raw_value string
---@return table
function _M.build_views(surface, raw_value)
    local cfg = config.get().normalization
    local safe_raw = raw_value or ""
    local safe_surf = safe_surface(surface)

    local url_decoded = decode_url_by_surface(safe_surf, safe_raw, cfg)
    local normalized_sqli = url_decoded
    local normalized_xss = url_decoded

    if cfg.html_entity_decode_for_xss then
        normalized_xss = decode_entity(normalized_xss, cfg.html_entity_decode_max_passes)
    end

    local model_sqli_input, sqli_truncated = fold_for_model(normalized_sqli, cfg)
    local model_xss_input, xss_truncated = fold_for_model(normalized_xss, cfg)

    return {
        raw_value = safe_raw,
        normalized_sqli_value = normalized_sqli,
        normalized_xss_value = normalized_xss,
        model_sqli_input = model_sqli_input,
        model_xss_input = model_xss_input,
        model_input_truncated = sqli_truncated or xss_truncated,
        invalid_utf8 = not is_valid_utf8(safe_raw),
        normalization_profile = cfg.active_profile
    }
end

return _M
