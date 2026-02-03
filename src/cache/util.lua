local cjson        = require("cjson.safe")
local cache        = require("cache.cache")

local _M = {
    WAF_WEIGHT_PREFIX          = 'waf_weight_prefix', -- waf 词袋权重前缀
    WAF_CONFIDENCE_PREFIX      = 'waf_confidence_prefix', -- waf 词袋置信度前缀

    WAF_BLOCK_PREFIX           = 'waf_block_prefix',
}

local cache_map    = {
    ['waf_weight_prefix'] = 'waf_w',
    ['waf_confidence_prefix'] = 'waf_c',
    ['waf_block_prefix'] = 'waf_block',
}

function _M.get_weight(type)
    local key_prefix    = _M.WAF_WEIGHT_PREFIX

    local key           = key_prefix .. ':' .. type

    local ok, err       = cache.resty_get(key, cache_map[key_prefix])

    if not ok or '' == ok then
        ok = {
            sample_count = 0,
            tokens       = {},
            tokens_hit   = {}
        }
    else
        ok = cjson.decode(ok)
    end

    return ok, err
end

function _M.set_weight(key, value)
    local key_prefix    = _M.WAF_WEIGHT_PREFIX

    local key           = key_prefix .. ':' .. key

    if type(value) ~= 'string' then
        value = cjson.encode(value)
    end

    local ok, err       = cache.resty_set(key, value, nil, cache_map[key_prefix])

    return ok, err
end


function _M.check_is_block(key)
    local key_prefix    = _M.WAF_BLOCK_PREFIX

    local key           = key_prefix .. ':' .. key

    local ok, err       = cache.resty_get(key, cache_map[key_prefix])

    if ok then
        ok = cjson.decode(ok)
    end

    return ok, err
end

function _M.set_block(key, value, expire)
    local key_prefix    = _M.WAF_BLOCK_PREFIX

    local key           = key_prefix .. ':' .. key
    value               = cjson.encode({attack_type = value})

    local ok, err       = cache.resty_set(key, value, expire, cache_map[key_prefix])
end


return _M