local _M = {}

local function present(value)
    return value and value ~= "" and value ~= "-"
end

local function safe_field_selector(surface, field_name, json_path)
    if surface == "json" and present(json_path) then
        return json_path
    end
    if present(field_name) then
        return field_name
    end
    return "-"
end

local function safe_signature(signature)
    if present(signature) then
        return signature
    end
    return "-"
end

local function escape_pipe(value)
    local escaped = tostring(value):gsub("|", "%%7C")
    return escaped
end

local function to_hex(binary)
    return (binary:gsub(".", function(ch)
        return string.format("%02x", string.byte(ch))
    end))
end

---构造 pattern_key_v1。
---格式串：method|route_key|content_type|surface|field_selector|detector|signature_token
function _M.build(ctx)
    local field_selector = safe_field_selector(ctx.surface, ctx.field_name, ctx.json_path)
    local signature_token = safe_signature(ctx.detector_signature)

    local parts = {
        escape_pipe(string.upper(ctx.method or "-")),
        escape_pipe(ctx.route_key or "-"),
        escape_pipe(ctx.content_type or "-"),
        escape_pipe(ctx.surface or "-"),
        escape_pipe(field_selector),
        escape_pipe(ctx.detector or "-"),
        escape_pipe(signature_token)
    }

    return table.concat(parts, "|")
end

---计算 pattern_key 的 sha256 十六进制哈希。
---@param pattern_key string
---@return string
function _M.sha256(pattern_key)
    local value = pattern_key or ""
    return to_hex(ngx.sha256_bin(value))
end

return _M
