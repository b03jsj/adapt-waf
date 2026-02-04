local config      = require("conf.config")

local ngx         = ngx

local _M          = {}

_M.DEBUG = 1
_M.INFO  = 2
_M.WARN  = 3
_M.ERROR = 4

local function get_level()
    return config.log.log_level
end

function _M.enabled(level)
    return level >= get_level()
end

function _M.debug(...)
    if not _M.enabled(_M.DEBUG) then
        return
    end
    ngx.log(ngx.DEBUG, ...)
end

function _M.info(...)
    if not _M.enabled(_M.INFO) then
        return
    end
    ngx.log(ngx.INFO, ...)
end

function _M.warn(...)
    if not _M.enabled(_M.WARN) then
        return
    end
    ngx.log(ngx.WARN, ...)
end

function _M.error(...)
    -- error 一般不关
    ngx.log(ngx.ERR, ...)
end


return _M
