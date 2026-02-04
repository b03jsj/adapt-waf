local xss_kw           = require("waf.runtime.xss_keywords")
local logger           = require("core.logger")

local _M = {
    total_key  = 'waf:score:meta:sample_count:',
    item_key   = 'waf:score:stat:token:',
}

local MAX_TOKEN_LEN = 64

local dict_weight = ngx.shared.waf_train

local function normalize(token)
    token = token:lower()
    if #token > MAX_TOKEN_LEN then
        token = token:sub(1, MAX_TOKEN_LEN)
    end
    return token
end

local function is_pure_digit(t)
    local len = #t
    if len == 0 then
        return false
    end
    for i = 1, len do
        local c = t:byte(i)
        if c < 48 or c > 57 then
            return false
        end
    end
    return true
end

local function strip_type(token)
    -- 找第一个 ':'，性能比正则高
    local p = token:find(":", 3, true)
    if not p then
        return nil
    end
    return token:sub(p + 1)
end

function _M.reset_cache()
    dict_weight:flush_all()
    dict_weight:flush_expired()
end

function _M.record_tokens(attack_type, tokens)
    if not attack_type or not tokens then return end

    logger.debug("record_tokens start")

    dict_weight:incr(_M.total_key .. attack_type, 1, 0)

    -- tokens 带了类型前缀
    for t in pairs(tokens) do
        local t_prefix = normalize(t)
        local token    = strip_type(t_prefix)

        if is_pure_digit(token) then
            goto continue
        end

        local key = _M.item_key .. attack_type .. ":token:" .. token

        if 'xss' == attack_type then
            -- 只取 __word:
            if t:sub(1, 7) == "__word:" then
                local word = t:sub(8)

                -- 只训练 XSS 强语义 token
                if xss_kw.is_strong(word) then
                    dict_weight:incr(key, 1, 0)
                end
            end
        else
            dict_weight:incr(key, 1, 0)
        end

        ::continue::
    end
end

function _M.dump_stats(attack_type)
    local prefix = _M.item_key .. attack_type .. ":token:"
    local out = {
        sample_count = dict_weight:get(_M.total_key .. attack_type) or 0,
        tokens = {}
    }

    for _, k in ipairs(dict_weight:get_keys(0)) do
        if k:sub(1, #prefix) == prefix then
            local _k = k:sub(#prefix + 1)

            out.tokens[_k] = dict_weight:get(k)
        end
    end

    return out
end

return _M
