local _M = {}

local dict_confidence = ngx.shared.waf_c

function _M.get(key)
    local cnt  = dict_confidence:get("cf:" .. key .. ":cnt") or 0
    if cnt < 10000 then
        return nil   -- 样本不足，不参与
    end

    local mean = dict_confidence:get("cf:" .. key .. ":mean")
    local m2   = dict_confidence:get("cf:" .. key .. ":m2")
    local var  = m2 / (cnt - 1)
    if var <= 0 then
        return nil
    end

    return mean, math.sqrt(var)
end

return _M
