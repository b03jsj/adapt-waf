local cache_util = require("cache.util")

local _M = {}

function _M.get(t)
    local weight = cache_util.get_weight(t)

    return weight
end

function _M.set(t, v)
    cache_util.set_weight(t, v)
end

return _M
