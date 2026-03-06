local cjson = require("cjson.safe")

local _M = {}

local cache = {}

local function join_path(prefix, suffix)
    if not prefix or prefix == "" then
        return suffix
    end
    if string.sub(prefix, -1) == "/" then
        return prefix .. suffix
    end
    return prefix .. "/" .. suffix
end

---返回默认配置文件路径。
---@return string
function _M.default_config_path()
    local prefix = ""
    if ngx and ngx.config and ngx.config.prefix then
        prefix = ngx.config.prefix() or ""
    end
    return join_path(prefix, "conf/waf-config.json")
end

---读取并解析 JSON 配置文件（按路径缓存）。
---@param path string
---@return table|nil, string|nil
function _M.load(path)
    if cache[path] ~= nil then
        return cache[path], nil
    end

    local f, open_err = io.open(path, "rb")
    if not f then
        return nil, "open_failed:" .. tostring(open_err)
    end

    local content = f:read("*a")
    f:close()
    if not content or content == "" then
        return nil, "empty_file"
    end

    local obj, decode_err = cjson.decode(content)
    if type(obj) ~= "table" then
        return nil, "decode_failed:" .. tostring(decode_err)
    end

    cache[path] = obj
    return obj, nil
end

return _M
