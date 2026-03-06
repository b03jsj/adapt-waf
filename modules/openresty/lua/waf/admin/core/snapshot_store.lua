local config = require("waf.admin.core.config")

local _M = {}

---将快照内容写入临时文件并原子替换目标文件。
---该操作仅用于低频管理接口，不在请求热路径执行。
---@return boolean, string|nil
function _M.atomic_write(content)
    local runtime_file = config.get().snapshot.runtime_file
    local tmp_file = runtime_file .. config.get().snapshot.tmp_suffix .. "." .. tostring(ngx.now())

    local f, open_err = io.open(tmp_file, "wb")
    if not f then
        return false, "open_tmp_failed:" .. tostring(open_err)
    end

    local ok, write_err = f:write(content)
    f:close()
    if not ok then
        return false, "write_tmp_failed:" .. tostring(write_err)
    end

    local rename_ok, rename_err = os.rename(tmp_file, runtime_file)
    if not rename_ok then
        return false, "rename_failed:" .. tostring(rename_err)
    end

    return true, nil
end

return _M
