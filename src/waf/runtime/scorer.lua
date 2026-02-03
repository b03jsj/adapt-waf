local loader           = require("waf.runtime.model_loader")
local ngram            = require("waf.runtime.ngram_boost")
local confidence       = require("waf.runtime.confidence")
local structure        = require("waf.runtime.structure")

local _M = {}

local LIMIT = {
    sqli  = {
        word    = 10.0,
        comment = 6.0,
        op      = 2.0,
        num     = 0.5
    },
    xss   = {
        word    = 3.0,
        comment = 1.5,
        op      = 3.0,
        num     = 0.2
    }
}

local function token_type(t)
    -- 第一个 ':' 的位置
    local p = t:find(":", 3, true)
    if not p then
        return nil
    end

    -- 拆类型和值
    local tp = t:sub(3, p - 1)
    local val = t:sub(p + 1)

    -- 只允许这 4 类（防脏数据）
    if tp == "word" or tp == "comment" or tp == "op" or tp == "num" then
        return tp, val
    end
end

local function build_features(tokens, bucket, score)
    local token_cnt = 0
    for _ in pairs(tokens) do
        token_cnt = token_cnt + 1
    end

    local total = bucket.word + bucket.comment + bucket.op + bucket.num + 1e-6

    return {
        token_cnt     = token_cnt,
        word_ratio    = bucket.word    / total,
        comment_ratio = bucket.comment / total,
        op_ratio      = bucket.op      / total,
        num_ratio     = bucket.num     / total,
        score         = score          -- 结构后分数
    }
end

function _M.score(api_ctx, attack_type)
    local model = loader.get(attack_type)

    if not model then return 0 end

    local max_score = 0
    local max_tokens = nil
    local max_bucket = nil

    for _, tokens in pairs(api_ctx.params_tokens or {}) do
        local bucket = {
            word = 0,
            comment = 0,
            op = 0,
            num = 0
        }

        for t in pairs(tokens) do
            local tp, val = token_type(t)
            if tp then
                bucket[tp] = bucket[tp] + (model.tokens[val] or 0)
            end
        end

        print("waf防护评分，word 贡献值：" .. tostring(bucket.word))
        print("waf防护评分，comment 贡献值：" .. tostring(bucket.comment))
        print("waf防护评分，op 贡献值：" .. tostring(bucket.op))
        print("waf防护评分，num 贡献值：" .. tostring(bucket.num))

        -- 应用上限
        local base =
            math.min(bucket.word,    LIMIT[attack_type].word) +
            math.min(bucket.comment, LIMIT[attack_type].comment) +
            math.min(bucket.op,      LIMIT[attack_type].op) +
            math.min(bucket.num,     LIMIT[attack_type].num)

        print("waf防护评分，应用上限后贡献值：" .. tostring(base))

        -- 补充执行符号匹配，按等级放大
        local structure, structure_score  = structure.has_exec_structure(tokens, attack_type)

        if base >= 3.0 then
            if structure == 1 then
                base = base * 1.25
            elseif structure == 2 then
                base = base * 2
            elseif structure == 0 then
                base = math.min(base, structure_score)
            end
        end

        print("waf防护评分，补充执行组合符号匹配后贡献值：" .. tostring(base))

        local score = ngram.apply(tokens, base, attack_type)

        print("waf防护评分，结构性放大后贡献值：" .. tostring(score))

        -- 取最大参数得分
        if score > max_score then
            max_score  = score
            max_tokens = tokens
            max_bucket = bucket
        end
    end

    -- 置信度
    local confidence_score = 0
    if max_score > 0 and max_tokens then
        local features   = build_features(max_tokens, max_bucket, max_score)

        confidence_score = confidence.calc(features, attack_type)

        api_ctx.waf_features  = features
    end

    print("waf防护评分，最终得分：" .. tostring(max_score))
    print("waf防护评分，置信度：" .. tostring(confidence_score))

    return max_score, confidence_score
end

return _M
