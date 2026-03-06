local cjson = require("cjson.safe")
local config = require("waf.interceptor.core.config")

local _M = {}

local function normalize_content_type(raw)
    if not raw or raw == "" then
        return "-"
    end
    local value = string.lower(raw)
    local semicolon = value:find(";", 1, true)
    if semicolon then
        return value:sub(1, semicolon - 1)
    end
    return value
end

local function string_value(value)
    if type(value) == "string" then
        return value
    end
    if type(value) == "number" or type(value) == "boolean" then
        return tostring(value)
    end
    return nil
end

local function clamp_value(value)
    if not value then
        return ""
    end
    local max_bytes = config.get().capture.max_value_bytes
    if #value <= max_bytes then
        return value
    end
    return value:sub(1, max_bytes)
end

local function append_field(fields, limit, surface, field_name, json_path, value)
    if #fields >= limit then
        return
    end
    local text = string_value(value)
    if not text then
        return
    end
    fields[#fields + 1] = {
        surface = surface,
        field_name = field_name or "-",
        json_path = json_path or "-",
        value = clamp_value(text)
    }
end

local function build_query_fields(fields)
    local limit = #fields + config.get().capture.max_query_fields
    local args = ngx.req.get_uri_args(limit)
    for key, value in pairs(args) do
        if #fields >= limit then
            break
        end
        local final_value = value
        if type(value) == "table" then
            final_value = value[1]
        end
        append_field(fields, limit, "query", tostring(key or "-"), "-", final_value)
    end
end

local function build_header_fields(fields, headers)
    local cfg = config.get().capture
    local limit = cfg.max_header_fields
    local absolute_limit = #fields + limit
    local count = 0

    for header, allowed in pairs(cfg.allowed_headers) do
        if not allowed then
            goto continue
        end

        if count >= limit then
            break
        end

        local value = headers[header]
        if type(value) == "table" then
            value = value[1]
        end
        if value ~= nil then
            append_field(fields, absolute_limit, "header", header, "-", value)
            count = count + 1
        end

        ::continue::
    end
end

local function flatten_json(fields, node, path, depth, limit)
    if #fields >= limit or depth > 6 then
        return
    end

    if type(node) == "table" then
        local is_array = (#node > 0)
        if is_array then
            for i, child in ipairs(node) do
                flatten_json(fields, child, string.format("%s[%d]", path, i), depth + 1, limit)
                if #fields >= limit then
                    return
                end
            end
        else
            for key, child in pairs(node) do
                local child_path = (path == "$") and ("$." .. tostring(key)) or (path .. "." .. tostring(key))
                flatten_json(fields, child, child_path, depth + 1, limit)
                if #fields >= limit then
                    return
                end
            end
        end
        return
    end

    append_field(fields, limit, "json", "-", path, node)
end

local function parse_json_fields(fields, body_raw)
    local obj, err = cjson.decode(body_raw)
    if not obj then
        return false, "json_decode_failed:" .. tostring(err)
    end
    local limit = #fields + config.get().capture.max_body_fields
    flatten_json(fields, obj, "$", 0, limit)
    return true, nil
end

local function parse_form_fields(fields, body_raw)
    local limit = #fields + config.get().capture.max_body_fields
    local args = ngx.decode_args(body_raw, limit)
    for key, value in pairs(args) do
        if #fields >= limit then
            break
        end
        local final_value = value
        if type(value) == "table" then
            final_value = value[1]
        end
        append_field(fields, limit, "form", tostring(key or "-"), "-", final_value)
    end
    return true, nil
end

local function parse_text_fields(fields, body_raw)
    append_field(fields, #fields + config.get().capture.max_body_fields, "text", "__body__", "-", body_raw)
    return true, nil
end

local function parse_multipart_fields(fields, body_raw)
    local limit = #fields + config.get().capture.max_body_fields
    for filename in body_raw:gmatch('filename="([^"]+)"') do
        if #fields >= limit then
            break
        end
        append_field(fields, limit, "multipart_filename", "__file__", "-", filename)
    end
    return true, nil
end

local function read_body_with_limit(max_bytes, allow_temp_file_readback)
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if body then
        return body, nil
    end

    local body_file = ngx.req.get_body_file()
    if not body_file then
        return nil, "body_empty"
    end

    if not allow_temp_file_readback then
        return nil, "body_in_temp_file"
    end

    local f, open_err = io.open(body_file, "rb")
    if not f then
        return nil, "temp_file_open_failed:" .. tostring(open_err)
    end
    local content = f:read(max_bytes)
    f:close()
    if not content then
        return nil, "temp_file_read_failed"
    end
    return content, nil
end

local function build_body_fields(fields, headers, content_type)
    local capture_cfg = config.get().capture
    local content_length = tonumber(headers["content-length"] or "")

    if not content_length then
        return false, "missing_content_length"
    end

    if content_length > capture_cfg.body_parse_hard_max_bytes then
        return false, "over_hard_max"
    end

    local parse_limit = math.min(capture_cfg.body_parse_max_bytes, capture_cfg.body_parse_hard_max_bytes)
    if content_length > parse_limit then
        return false, "over_parse_limit"
    end

    local is_multipart = (content_type or ""):find("multipart/form-data", 1, true) ~= nil
    local allowed = capture_cfg.allowed_content_types[content_type] == true
    if (not is_multipart) and (not allowed) then
        return false, "content_type_not_allowed"
    end

    local body_raw, body_err = read_body_with_limit(parse_limit, capture_cfg.allow_temp_file_readback)
    if not body_raw then
        return false, body_err
    end

    if is_multipart then
        return parse_multipart_fields(fields, body_raw)
    end
    if content_type == "application/json" then
        return parse_json_fields(fields, body_raw)
    end
    if content_type == "application/x-www-form-urlencoded" then
        return parse_form_fields(fields, body_raw)
    end
    if content_type == "text/plain" then
        return parse_text_fields(fields, body_raw)
    end

    return false, "unsupported_content_type"
end

---构建检测与日志所需的归一化请求上下文。
---该方法应尽量减少分配并保持非阻塞。
function _M.build()
    local headers = ngx.req.get_headers(64, true)
    local content_type = normalize_content_type(headers["content-type"])
    local ua = headers["user-agent"] or "-"
    local method = ngx.req.get_method()
    local route_key = ngx.var.uri or "-"

    local fields = {}
    build_query_fields(fields)
    build_header_fields(fields, headers)
    local body_inspected, body_skip_reason = build_body_fields(fields, headers, content_type)

    local ctx = {
        request_id = ngx.var.request_id or tostring(ngx.now()),
        method = string.upper(method),
        route_key = route_key,
        host = headers["host"] or "-",
        content_type = content_type,
        content_length = tonumber(headers["content-length"] or "") or 0,
        surface = "query",
        field_name = "-",
        json_path = "-",
        detector = "-",
        detector_signature = "-",
        client_ip = ngx.var.remote_addr or "-",
        user_agent = ua,
        user_agent_hash = ngx.md5(ua),
        mode = config.get().mode,
        fields = fields,
        body_inspected = body_inspected,
        body_skip_reason = body_skip_reason,
        matched_value = "",
        pattern_key = "-",
        pattern_key_hash = "-"
    }

    return ctx
end

return _M
