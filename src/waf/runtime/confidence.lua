local model = require("waf.runtime.confidence_model")

local _M = {}

local function sigmoid(x)
    return 1 / (1 + math.exp(-x))
end

-- 0 不像正常流量 --> 1 靠近正常流量
function _M.calc(features, attack_type)
    local zsum = 0
    local used = 0

    for k, v in pairs(features) do
        local mean, std = model.get(k)
        if mean and std then
            local z = math.abs(v - mean) / std
            zsum = zsum + z
            used = used + 1
        end
    end

    if used == 0 then
        return 1.0 -- 不确定 → 偏安全
    end

    local zavg = zsum / used
    return 1 - sigmoid(zavg)
end

return _M
