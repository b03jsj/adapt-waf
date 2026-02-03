local _M = {}

-- 重新计算 weight
local function calc_weight(count, total)
    if count <= 0 or total <= 0 then
        return 0
    end
    return math.log(1 + count / total)
end

function _M.merge(old_stats, new_stats)
    local merged = {
        sample_count = old_stats.sample_count + new_stats.sample_count,
        tokens       = {},
        tokens_hit   = {}
    }

    -- 先合并旧
    for t, c in pairs(old_stats.tokens_hit) do
        merged.tokens_hit[t] = c
    end

    -- 再加新
    for t, c in pairs(new_stats.tokens) do
        merged.tokens_hit[t] = (merged.tokens_hit[t] or 0) + c
    end

    return merged
end


return _M
