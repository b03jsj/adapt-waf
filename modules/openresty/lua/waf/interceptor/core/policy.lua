local config = require("waf.interceptor.core.config")

local _M = {}

local function calc_sgd_weight(signals)
    local model_cfg = config.get().model or {}
    local release_state = string.lower(tostring(signals.sgd_model_state or "disabled"))
    local load_state = string.lower(tostring(signals.sgd_model_load_state or "disabled"))

    -- 兼容旧字段：未拆分 load/release 状态时，沿用 active 语义。
    if signals.sgd_model_load_state == nil and release_state == "active" then
        load_state = "active"
        release_state = "stable"
    end

    if load_state ~= "active" then
        return 0
    end

    local active_release_states = model_cfg.sgd_active_release_states or { stable = true }
    if active_release_states[release_state] then
        return 1
    end

    return 0
end

local function base_decision(mode)
    return {
        mode = mode,
        decision_candidate = "allow",
        final_action = "allow",
        enforced_action = "allow",
        policy_decision_basis = "none",
        threat_classification = "none",
        alert_level = "none",
        status = ngx.HTTP_OK,
        budget_exhausted = false,
        sgd_decision_weight = 0,
        sgd_score_used = 0
    }
end

---构造黑名单命中的动作决策。
function _M.decide_blacklist_hit(_, meta)
    local decision = base_decision(config.get().mode)
    decision.decision_candidate = "block"
    decision.final_action = "block"
    decision.enforced_action = "block"
    decision.policy_decision_basis = "blacklist_hit"
    decision.threat_classification = "confirmed_attack"
    decision.alert_level = "critical"
    decision.status = ngx.HTTP_FORBIDDEN
    decision.blacklist_key = meta and meta.key or "-"
    decision.reputation_score = meta and meta.score or 0
    return decision
end

---构造检测超时后的 fail-open 决策。
---@param stage string
---@param elapsed_ms number
---@param hard_timeout_ms number
function _M.decide_timeout(stage, elapsed_ms, hard_timeout_ms)
    local decision = base_decision(config.get().mode)
    decision.decision_candidate = "allow"
    decision.final_action = "allow"
    decision.enforced_action = "allow"
    decision.policy_decision_basis = "timeout_fail_open"
    decision.threat_classification = "suspected_attack"
    decision.alert_level = "high"
    decision.timeout_stage = stage
    decision.elapsed_ms = elapsed_ms
    decision.hard_timeout_ms = hard_timeout_ms
    decision.budget_exhausted = true
    return decision
end

local function handle_parser_hit(mode, decision, exemption_match, signals)
    if exemption_match and exemption_match.applied then
        decision.decision_candidate = "allow"
        decision.final_action = "allow"
        decision.enforced_action = "allow"
        decision.threat_classification = "suspected_attack"
        decision.alert_level = "high"
        if exemption_match.match_scope == "detector_field" then
            decision.policy_decision_basis = "parser_hit_exempted_detector_field"
        else
            decision.policy_decision_basis = "parser_hit_exempted_exact"
        end
        return
    end

    if mode == "shadow" then
        decision.decision_candidate = "log"
        decision.final_action = "log"
        decision.enforced_action = "allow"
        decision.policy_decision_basis = "parser_hit_shadow"
        decision.threat_classification = "suspected_attack"
        decision.alert_level = "high"
        return
    end

    if mode == "assist" then
        local pattern_state = tostring((signals and signals.pattern_state) or "unknown")
        if pattern_state == "benign_confirmed" then
            decision.decision_candidate = "log"
            decision.final_action = "log"
            decision.enforced_action = "allow"
            decision.policy_decision_basis = "parser_hit_assist_known_benign"
            decision.threat_classification = "suspected_attack"
            decision.alert_level = "low"
            return
        end

        decision.decision_candidate = "high_alert"
        decision.final_action = "high_alert"
        decision.enforced_action = "allow"
        if pattern_state == "attack_confirmed" then
            decision.policy_decision_basis = "parser_hit_assist_known_attack"
            decision.alert_level = "critical"
        else
            decision.policy_decision_basis = "parser_hit_assist_first_seen"
            decision.alert_level = "high"
        end
        decision.threat_classification = "suspected_attack"
        return
    end

    decision.decision_candidate = "block"
    decision.final_action = "block"
    decision.enforced_action = "block"
    decision.policy_decision_basis = "parser_hit_block"
    decision.threat_classification = "confirmed_attack"
    decision.alert_level = "critical"
    decision.status = ngx.HTTP_FORBIDDEN
end

---构造普通检测路径的动作决策。
function _M.decide(_, signals, exemption_match)
    local mode = config.get().mode
    local detector_cfg = config.get().detector
    local decision = base_decision(mode)
    local sgd_raw = tonumber(signals.sgd_score or 0)
    local sgd_weight = calc_sgd_weight(signals)
    local sgd_used = sgd_raw * sgd_weight
    decision.sgd_decision_weight = sgd_weight
    decision.sgd_score_used = sgd_used

    if signals.detector_unavailable == true then
        decision.final_action = (mode == "shadow") and "log" or "high_alert"
        decision.decision_candidate = decision.final_action
        decision.enforced_action = "allow"
        decision.policy_decision_basis = "detector_unavailable_fail_open"
        decision.threat_classification = "suspected_attack"
        decision.alert_level = "high"
        return decision
    end

    if signals.parser_hit then
        handle_parser_hit(mode, decision, exemption_match, signals)
        return decision
    end

    if signals.weak_signal_score >= detector_cfg.weak_signal_threshold
            and sgd_used >= detector_cfg.sgd_high_threshold then
        decision.decision_candidate = "high_alert"
        decision.final_action = "high_alert"
        decision.enforced_action = "allow"
        decision.policy_decision_basis = "weak_combo_only"
        decision.threat_classification = "suspected_attack"
        decision.alert_level = "high"
        return decision
    end

    if sgd_used >= detector_cfg.model_only_sample_threshold then
        decision.decision_candidate = "sample_only"
        decision.final_action = "sample_only"
        decision.enforced_action = "allow"
        decision.policy_decision_basis = "model_only"
        decision.threat_classification = "sample_only"
        decision.alert_level = "low"
        return decision
    end

    return decision
end

return _M
