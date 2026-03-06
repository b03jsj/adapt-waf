local cjson = require("cjson.safe")
local auth = require("waf.admin.core.auth")
local generation_store = require("waf.admin.core.generation_store")
local snapshot_store = require("waf.admin.core.snapshot_store")

local _M = {}

local function to_hex(binary)
    return (binary:gsub(".", function(ch)
        return string.format("%02x", string.byte(ch))
    end))
end

local function sha256_hex(value)
    return to_hex(ngx.sha256_bin(value))
end

local function read_raw_body()
    local raw = ngx.req.get_body_data()
    if raw then
        return raw, nil
    end

    local body_file = ngx.req.get_body_file()
    if not body_file then
        return nil, "empty_body"
    end

    local f, open_err = io.open(body_file, "rb")
    if not f then
        return nil, "body_file_open_failed:" .. tostring(open_err)
    end
    local content = f:read("*a")
    f:close()
    if not content then
        return nil, "body_file_read_failed"
    end
    return content, nil
end

local function read_json_body()
    ngx.req.read_body()
    local raw, raw_err = read_raw_body()
    if not raw then
        return nil, nil, raw_err
    end
    local obj, err = cjson.decode(raw)
    if not obj then
        return nil, nil, "invalid_json:" .. tostring(err)
    end
    return raw, obj, nil
end

local function decode_snapshot_base64(payload)
    local encoded = payload.compiled_content_base64
    if not encoded then
        return nil, "missing_compiled_content_base64"
    end
    local decoded = ngx.decode_base64(encoded)
    if not decoded then
        return nil, "base64_decode_failed"
    end
    return decoded, nil
end

local function validate_snapshot_payload(payload, snapshot)
    local declared_size = tonumber(payload.compiled_size or 0)
    if declared_size > 0 and declared_size ~= #snapshot then
        return false, "compiled_size_mismatch"
    end

    local declared_sha256 = tostring(payload.compiled_sha256 or "")
    if declared_sha256 ~= "" then
        declared_sha256 = declared_sha256:gsub("^sha256:", "")
        local current_sha256 = sha256_hex(snapshot)
        if declared_sha256 ~= current_sha256 then
            return false, "compiled_sha256_mismatch"
        end
    end

    local obj, err = cjson.decode(snapshot)
    if not obj then
        return false, "compiled_json_invalid:" .. tostring(err)
    end

    if obj.schema_version ~= "exemptions-compiled-v1" then
        return false, "compiled_schema_invalid"
    end
    if type(obj.rules) ~= "table" then
        return false, "compiled_rules_missing"
    end

    local payload_generation = tonumber(payload.generation)
    local snapshot_generation = tonumber(obj.generation)
    if payload_generation ~= snapshot_generation then
        return false, "compiled_generation_mismatch"
    end

    return true, nil
end

---处理 publish 接口。
---约束：generation 必须单调递增；回退通过新 generation 重发旧内容实现。
function _M.handle()
    local raw_body, payload, payload_err = read_json_body()
    if not payload then
        ngx.status = ngx.HTTP_BAD_REQUEST
        ngx.say(cjson.encode({ error = payload_err }))
        return
    end

    local ok, auth_err = auth.authorize(raw_body)
    if not ok then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.say(cjson.encode({ error = auth_err }))
        return
    end

    local generation = tonumber(payload.generation)
    local max_generation = generation_store.get_max_generation()
    if not generation or generation <= max_generation then
        ngx.status = ngx.HTTP_BAD_REQUEST
        ngx.say(cjson.encode({
            error = "generation_not_monotonic",
            current_generation = generation_store.get_current_generation(),
            target_generation = generation_store.get_target_generation(),
            max_generation = max_generation
        }))
        return
    end

    local snapshot, decode_err = decode_snapshot_base64(payload)
    if not snapshot then
        generation_store.set_failed(decode_err)
        ngx.status = ngx.HTTP_BAD_REQUEST
        ngx.say(cjson.encode({ error = decode_err }))
        return
    end

    local valid_snapshot, snapshot_err = validate_snapshot_payload(payload, snapshot)
    if not valid_snapshot then
        generation_store.set_failed(snapshot_err)
        ngx.status = ngx.HTTP_BAD_REQUEST
        ngx.say(cjson.encode({ error = snapshot_err }))
        return
    end

    local write_ok, write_err = snapshot_store.atomic_write(snapshot)
    if not write_ok then
        generation_store.set_failed(write_err)
        ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
        ngx.say(cjson.encode({ error = write_err }))
        return
    end

    local target_ok, target_err = generation_store.set_target(
        generation,
        payload.compiled_sha256 or "-",
        payload.compiled_size or 0
    )
    if not target_ok then
        ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
        ngx.say(cjson.encode({ error = target_err }))
        return
    end

    ngx.status = ngx.HTTP_OK
    ngx.say(cjson.encode({
        accepted = true,
        generation = generation,
        publish_id = payload.publish_id
    }))
end

return _M
