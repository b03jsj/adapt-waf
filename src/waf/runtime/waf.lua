local scorer    = require("waf.runtime.scorer")
local extractor = require("waf.runtime.extractor")

local _M = {}

function _M.inspect(api_ctx, inspect)
    extractor.extract(api_ctx)

    for t, th in pairs(inspect) do
        print("waf拦截，检测攻击开始，检测项【" .. t .. "】")

        local max_score, confidence_score = scorer.score(api_ctx, t)

        if max_score >= th.hard_block.score then
            print("waf拦截，检测到攻击，命中【" .. t .. "】，评分：" .. tostring(max_score))

            return true, t
        elseif max_score >= th.soft_block.score
                and confidence_score <= th.soft_block.confidence then

            print("waf拦截，检测到攻击，命中【" .. t .. "】，评分：" .. tostring(max_score))
            print("waf拦截，检测到攻击，置信度：" .. tostring(confidence_score))

            return true, t
        end
    end

    return false
end

return _M
