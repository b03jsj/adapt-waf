local _M = {}


local RULES = {
    sqli = {
        -- ========= SQL 结构成型 =========
        {
            tokens = { "__word:select", "__word:from" },
            boost  = 0.30
        },
        {
            tokens = { "__word:select", "__word:where" },
            boost  = 0.30
        },
        {
            tokens = { "__word:insert", "__word:into" },
            boost  = 0.35
        },
        {
            tokens = { "__word:update", "__word:set" },
            boost  = 0.35
        },
        {
            tokens = { "__word:delete", "__word:from" },
            boost  = 0.35
        },

        -- ========= UNION / 子查询 =========
        {
            tokens = { "__word:union", "__word:select" },
            boost  = 0.40
        },
        {
            tokens = { "__word:select", "__word:select" }, -- 子查询
            boost  = 0.30
        },

        -- ========= 注释 + 关键字 =========
        {
            tokens = { "__word:select", "__comment:**" },
            boost  = 0.25
        },
        {
            tokens = { "__word:union", "__comment:**" },
            boost  = 0.25
        },

        -- ========= 布尔注入 =========
        {
            tokens = { "__word:or", "__num:1" },
            boost  = 0.20
        },
        {
            tokens = { "__word:and", "__word:sleep" },
            boost  = 0.30
        },
        {
            tokens = { "__word:benchmark", "__op:(" },
            boost  = 0.35
        },

        -- ========= 系统表 / 信息泄露 =========
        {
            tokens = { "__word:information_schema", "__word:tables" },
            boost  = 0.35
        },
        {
            tokens = { "__word:information_schema", "__word:columns" },
            boost  = 0.35
        },

        -- ========= 函数拼接 / 绕过 =========
        {
            tokens = { "__word:chr", "__op:||", "__word:chr" },
            boost  = 0.25
        },
        {
            tokens = { "__word:char", "__op:||", "__word:char" },
            boost  = 0.25
        },
        {
            tokens = { "__word:concat", "__op:(" },
            boost  = 0.20
        },

        -- ========= Oracle 特有 =========
        {
            tokens = { "__word:dbms_pipe.receive_message", "__op:||" },
            boost  = 0.40
        }
    },
    xss = {
        -- ========= <script> 执行型 =========
        {
            tokens = { "__word:script", "__word:alert" },
            boost  = 0.30
        },
        {
            tokens = { "__word:script", "__word:eval" },
            boost  = 0.35
        },
        {
            tokens = { "__word:script", "__word:document" },
            boost  = 0.30
        },
        -- ========= 事件 + JS 调用 =========
        {
            tokens = { "__word:onerror", "__word:alert" },
            boost  = 0.40
        },
        {
            tokens = { "__word:onload", "__word:alert" },
            boost  = 0.35
        },
        {
            tokens = { "__word:onclick", "__word:alert" },
            boost  = 0.30
        },
        {
            tokens = { "__word:onmouseover", "__word:alert" },
            boost  = 0.30
        },
        -- ========= JS API 执行链 =========
        {
            tokens = { "__word:document", "__word:cookie" },
            boost  = 0.35
        },
        {
            tokens = { "__word:document", "__word:location" },
            boost  = 0.30
        },
        {
            tokens = { "__word:window", "__word:location" },
            boost  = 0.30
        },
        -- ========= JS 函数执行 + 结构符号 =========
        {
            tokens = { "__word:eval", "__op:(" },
            boost  = 0.40
        },
        {
            tokens = { "__word:alert", "__op:(" },
            boost  = 0.25
        },
        {
            tokens = { "__word:confirm", "__op:(" },
            boost  = 0.25
        },
        {
            tokens = { "__word:prompt", "__op:(" },
            boost  = 0.25
        },
        -- ========= 协议型 XSS =========
        {
            tokens = { "__word:javascript", "__word:alert" },
            boost  = 0.40
        },
        {
            tokens = { "__word:javascript", "__word:eval" },
            boost  = 0.45
        },
        -- ========= SVG / IMG 绕过 =========
        {
            tokens = { "__word:svg", "__word:onload" },
            boost  = 0.40
        },
        {
            tokens = { "__word:img", "__word:onerror" },
            boost  = 0.40
        },
        -- ========= 强执行链（单条即危险） =========
        {
            tokens = { "__word:onerror", "__op:=", "__word:alert", "__op:(" },
            boost  = 0.60
        },
        {
            tokens = { "__word:onload", "__op:=", "__word:eval", "__op:(" },
            boost  = 0.65
        },
        {
            tokens = { "__word:javascript", "__op::", "__word:alert", "__op:(" },
            boost  = 0.70
        },
    }
}

local function has_all(tokens, need)
    for _, t in ipairs(need) do
        if not tokens[t] then
            return false
        end
    end
    return true
end

function _M.apply(param_tokens, base_score, attack_type)
    -- 低分不放大（防误杀）
    if base_score < 3.0 then
        return base_score
    end

    local boost = 0

    for _, rule in ipairs(RULES[attack_type]) do
        if has_all(param_tokens, rule.tokens) then
            boost = boost + rule.boost
        end
    end

    -- 总放大上限 40%
    boost = math.min(boost, 0.4)

    return base_score * (1 + boost)
end

return _M
