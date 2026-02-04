local logger   = require("core.logger")

local _M = {}

local DICTS = {
    waf_w     = ngx.shared.waf_w,
    waf_c     = ngx.shared.waf_c,
    waf_block = ngx.shared.waf_block,
}

local function get_resty_cache(resty_zone)
    return DICTS[resty_zone]
end


local function resty_get(key, resty_zone)
    local ok, err = get_resty_cache(resty_zone):get(key)

    if not ok then
        logger.debug("dict cmd【get】err，【key】:" , key , " err：", err)
    end

    return ok, err
end

local function resty_set(key, value, expire, resty_zone)
    if not expire or -1 == expire then
        expire = 0
    end

    local ok, err = get_resty_cache(resty_zone):set(key, value, expire)

    if not ok then
        logger.debug("dict cmd【set】err，【key】:" , key , " err：", err)
    end

    return ok, err
end

_M.resty_get          = resty_get
_M.resty_set          = resty_set

return _M