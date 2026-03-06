local config = require("waf.interceptor.core.config")

local _M = {}

local function get_dict()
    local dict_name = config.get().blacklist.dict_name
    return ngx.shared[dict_name]
end

---构造黑名单键。
---默认键为 ip + user_agent_hash，以降低 NAT 场景误伤。
function _M.build_key(ctx)
    local cfg = config.get().blacklist
    return string.format("%s%s%s", ctx.client_ip or "-", cfg.key_delimiter, ctx.user_agent_hash or "-")
end

function _M.init()
    -- 预留：后续可增加预热逻辑。
end

---检查当前请求是否命中黑名单。
---@return boolean, table
function _M.hit(ctx)
    local dict = get_dict()
    if not dict then
        return false, { reason = "dict_missing" }
    end

    local key = _M.build_key(ctx)
    local score = dict:get(key)
    if not score then
        return false, { key = key, score = 0 }
    end

    return true, { key = key, score = score }
end

local function should_promote(runtime)
    local decision = runtime and runtime.decision or {}
    local action = decision.final_action
    return action == "block" or action == "high_alert"
end

---在 log 阶段根据最终信号更新信誉分。
---该更新不会改变当前请求动作，只影响后续请求。
function _M.update_from_runtime(runtime)
    if not runtime or not should_promote(runtime) then
        return
    end

    local ctx = runtime.context or {}
    local dict = get_dict()
    if not dict then
        return
    end

    local cfg = config.get().blacklist
    local key = _M.build_key(ctx)
    local score = dict:incr(key, 1, 0, cfg.ttl_seconds)
    if not score then
        return
    end

    runtime.signals.reputation_blacklist_key = key
    runtime.signals.reputation_score = score
    runtime.signals.reputation_blacklist_hit = score >= cfg.score_threshold
end

return _M
