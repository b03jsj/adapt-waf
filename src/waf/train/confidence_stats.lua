local dict_confidence = ngx.shared.waf_c

local _M = {}

local function update_stat(key, x)
    local cnt = dict_confidence:incr(key .. ":cnt", 1, 0)
    local mean = dict_confidence:get(key .. ":mean") or 0
    local m2   = dict_confidence:get(key .. ":m2")   or 0

    local delta = x - mean
    mean = mean + delta / cnt
    local delta2 = x - mean
    m2 = m2 + delta * delta2

    dict_confidence:set(key .. ":mean", mean)
    dict_confidence:set(key .. ":m2", m2)
end

-- 正常流量走学习
function _M.record(api_ctx)
    local features  = api_ctx.waf_features

    if not features then
        return
    end

    -- 采样 20%
    if math.random() > 0.2 then
        return
    end

    for k, v in pairs(features) do
        if type(v) == "number" then
            update_stat("cf:" .. k, v)
        end
    end
end

return _M
