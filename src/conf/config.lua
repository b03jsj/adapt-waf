
local waf         = {
    mode          = 'intercept', -- train | observe（观察） | intercept（拦截） | off 停用
    inspect       = {
        sqli = {      -- 高于 hard_block 则命中、介于 soft_block hard_block之间，计算可信度
            hard_block = {
                score = 8.0
            },
            soft_block = {
                score = 3.5,
                confidence = 0.30  -- 可信度
            }
        },
        xss = {
            hard_block = {
                score = 6.0
            },
            soft_block = {
                score = 3.0,
                confidence = 0.35
            }
        }
    },
    block         = {
        seconds   = 3600, -- 拦截时长，单位秒
    },
    train         = {
        type      = 'sqli', -- sqli | xss
    },
    confidence    = {
        flag      = true,  -- 是否开启可信度训练
        sample    = 0.2, -- 20% 正常流量采样率
    }
}

local log = {
    log_level = 4  -- DEBUG 1   INFO 2   WARN 3   ERROR 4
}

local config = {waf = waf, log = log}


return config