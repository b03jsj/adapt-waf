local extractor = require("waf.runtime.extractor")
local stats     = require("waf.train.stats")
local merge     = require("waf.train.merge")
local loader    = require("waf.runtime.model_loader")

local _M = {}

local function round4(x)
    return math.floor(x * 10000 + 0.5) / 10000
end

local function calc_weight(hit)
    local ln  = math.log(1 + hit)

    return round4(ln)
end


function _M.train_start(api_ctx, attack_type)
    -- 抽取 params_tokens
    local params_tokens = extractor.extract(api_ctx)

    -- 针对“攻击样本”，逐参数记录
    for _, tokens in pairs(params_tokens or {}) do
        stats.record_tokens(attack_type, tokens)
    end
end

function _M.export(attack_type)
    local new_stats    = stats.dump_stats(attack_type)
    local old_stats    = loader.get(attack_type)

    -- 合并
    local merged_stats = merge.merge(old_stats, new_stats)

    local model = {
        sample_count = merged_stats.sample_count or 0,
        tokens       = {},
        tokens_hit   = {}
    }
    for token, hit in pairs(merged_stats.tokens_hit) do
        model.tokens[token] = calc_weight(hit)
        model.tokens_hit[token] = hit
    end

    if next(model.tokens_hit) ~= nil then
        loader.set(attack_type, model)
    end

    -- 清理缓存
    stats.reset_cache()
end


return _M