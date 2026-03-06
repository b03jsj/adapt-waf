local config = require("waf.admin.core.config")

local _M = {}

local function to_hex(binary)
    return (binary:gsub(".", function(ch)
        return string.format("%02x", string.byte(ch))
    end))
end

local function sha256_hex(value)
    return to_hex(ngx.sha256_bin(value))
end

local function check_timestamp(raw_timestamp)
    local ts = tonumber(raw_timestamp or "")
    if not ts then
        return false, "missing_or_invalid_timestamp"
    end

    local now = ngx.time()
    if math.abs(now - ts) > 300 then
        return false, "timestamp_out_of_window"
    end

    return true, nil
end

local function check_nonce(raw_nonce)
    if not raw_nonce or raw_nonce == "" then
        return false, "missing_nonce"
    end

    local dict = ngx.shared.waf_control
    if not dict then
        return false, "auth_dict_missing"
    end

    local ok, err = dict:add("auth_nonce:" .. raw_nonce, 1, 300)
    if not ok then
        if err == "exists" then
            return false, "nonce_replay"
        end
        return false, "nonce_store_failed"
    end

    return true, nil
end

---执行管理接口鉴权。
---签名规范：sha256_hex(timestamp + "|" + nonce + "|" + sha256_hex(body) + "|" + shared_secret)。
---@return boolean, string|nil
function _M.authorize(raw_body)
    local auth_cfg = config.get().auth or {}
    if auth_cfg.require_mtls == true then
        local verify = ngx.var.ssl_client_verify or ""
        if verify ~= "SUCCESS" then
            return false, "mtls_required"
        end
    end

    if auth_cfg.require_signature == false then
        return true, nil
    end

    local headers = ngx.req.get_headers()
    local signature = headers["x-waf-signature"]
    local timestamp = headers["x-waf-timestamp"]
    local nonce = headers["x-waf-nonce"]

    if not signature or signature == "" then
        return false, "missing_signature"
    end

    local ts_ok, ts_err = check_timestamp(timestamp)
    if not ts_ok then
        return false, ts_err
    end

    local nonce_ok, nonce_err = check_nonce(nonce)
    if not nonce_ok then
        return false, nonce_err
    end

    local shared_secret = tostring(auth_cfg.shared_secret or "change_me")
    local body_sha256 = sha256_hex(raw_body or "")
    local expected = sha256_hex(tostring(timestamp) .. "|" .. tostring(nonce) .. "|" .. body_sha256 .. "|" .. shared_secret)
    if expected ~= signature then
        return false, "invalid_signature"
    end

    return true, nil
end

return _M
