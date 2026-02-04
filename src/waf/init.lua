local config           = require("conf.config")
local logger           = require("core.logger")
local waf              = require("waf.runtime.waf")
local confidence_stats = require("waf.train.confidence_stats")
local cache_util       = require("cache.util")
local weights          = require("conf.weights")
local ctx              = require("core.ctx")

local _M = {}

function _M.init_worker()
    logger.debug("waf，初始化权重")

    for k, v in pairs(weights) do
        cache_util.set_weight(k, v)
    end
end

-- 做拦截
function _M.access()
    local api_ctx   = ctx.init()

    local waf_conf        = config.waf or {}
    local mode            = waf_conf.mode or 'observe'

    if 'off' == mode then
        return
    end

    logger.debug("waf拦截，检测当前IP是否被拦截")

    local client_ip = api_ctx.req.client_ip

    local rs = cache_util.check_is_block(client_ip)

    if rs then
        logger.error("waf拦截，当前IP被拦截，访问拒绝，拦截项：" , rs.attack_type)

        ngx.exit(403)
    end
end

-- 匹配，如果要拦截 入缓存
function _M.log()
    local api_ctx         = ngx.ctx.api_ctx

    local waf_conf        = config.waf or {}
    local mode            = waf_conf.mode or 'observe'

    if 'off' == mode then
        ctx.log(api_ctx)

        return
    end

    if 403 == ngx.status then
        ctx.log(api_ctx)

        return
    end

    local func =  function(premature)
        if premature then
            return
        end

        if 'observe' == mode or 'intercept' == mode then
            local inspect         = waf_conf.inspect or {}

            local rs, attack_type = waf.inspect(api_ctx, inspect)

            if true == rs and 'intercept' == mode then
                logger.error("waf拦截，检测攻击被命中，拦截模式，记入拦截黑名单")

                local client_ip = api_ctx.req.client_ip
                local expire    = config.waf.block.seconds or 3600 -- 秒

                cache_util.set_block(client_ip, attack_type, expire)
            end

            -- 置信度学习
            local confidence_conf = waf_conf.confidence or {}
            local flag            = confidence_conf.flag or false
            if true == flag then
                -- 根据正常流量训练置信度样本
                confidence_stats.record(api_ctx)
            end

            ctx.log(api_ctx)
        end
    end
    ngx.timer.at(0, func)
end


return _M