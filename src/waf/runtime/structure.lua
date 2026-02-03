local _M = {}

local STRUCTURE_RULES = {
    xss = {
        {
            level = 2,
            exact = { "__op:<", "__op:>", "__word:script" }
        },


        {
            level = 2,
            exact = { "__word:javascript", "__op::" }
        },


        {
            level = 2,
            exact = { "__word:svg", "__word:onload", "__op:=" }
        },
        {
            level = 2,
            exact = { "__word:img", "__word:onerror", "__op:=" }
        },


        {
            level = 1,
            exact = { "__op:(", "__op:)" },
            prefix = { "__word:" }
        },


        {
            level = 1,
            exact = { "__op:=" },
            prefix = { "__word:on" }
        }
    }

}

local NO_STRUCTURE_OP_MAX_SCORE = {
    xss = 3.5 -- 没有结构性操作，分值上限
}

local function match_exact(tokens, exact)
    for _, t in ipairs(exact or {}) do
        if not tokens[t] then
            return false
        end
    end
    return true
end

local function match_prefix(tokens, prefixes)
    if not prefixes then
        return true
    end

    for k in pairs(tokens) do
        for _, p in ipairs(prefixes) do
            if k:sub(1, #p) == p then
                return true
            end
        end
    end

    return false
end

function _M.has_exec_structure(tokens, attack_type)
    local max_score = NO_STRUCTURE_OP_MAX_SCORE[attack_type] or 9999
    local rules     = STRUCTURE_RULES[attack_type]

    if not rules then
        return 0, max_score
    end

    local hit_level = 0

    for _, rule in ipairs(rules) do
        if match_exact(tokens, rule.exact)
                and match_prefix(tokens, rule.prefix)
        then
            if rule.level > hit_level then
                hit_level = rule.level
            end
        end
    end

    return hit_level, max_score
end

return _M
