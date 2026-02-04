local scorer           = require("waf.runtime.scorer")
local extractor        = require("waf.runtime.extractor")
local logger           = require("core.logger")

local _M = {}

function _M.inspect(api_ctx, inspect)
    extractor.extract(api_ctx)

    for t, th in pairs(inspect) do
        logger.debug("waf拦截，检测攻击开始，检测项【" , t , "】")

        local max_score, confidence_score = scorer.score(api_ctx, t)

        if max_score >= th.hard_block.score then
            logger.error("waf拦截，检测到攻击，命中【" , t , "】，评分：" , max_score)

            return true, t
        elseif max_score >= th.soft_block.score
                and confidence_score <= th.soft_block.confidence then

            logger.error("waf拦截，检测到攻击，命中【" , t , "】，评分：" , max_score)
            logger.error("waf拦截，检测到攻击，置信度：" , confidence_score)

            return true, t
        end
    end

    return false
end

return _M
