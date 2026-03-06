local cjson = require("cjson.safe")

local _M = {}

local function now_utc_iso8601()
    return os.date("!%Y-%m-%dT%H:%M:%SZ")
end

local function is_alert(payload)
    if payload.alert_level == "critical" or payload.alert_level == "high" then
        return true
    end
    if payload.final_action == "block"
            or payload.final_action == "high_alert"
            or payload.final_action == "log" then
        return true
    end
    if payload.policy_decision_basis == "timeout_fail_open" then
        return true
    end
    return false
end

local function should_sample(payload, sample_rate)
    if payload.final_action == "sample_only" then
        return true
    end

    if is_alert(payload) then
        return false
    end

    if payload.final_action ~= "allow" then
        return false
    end

    local rate = tonumber(sample_rate or 0) or 0
    if rate <= 0 then
        return false
    end
    if rate >= 1 then
        return true
    end

    local seed = payload.event_id or tostring(ngx.now())
    local hash = ngx.crc32_short(seed)
    return (hash % 10000) < math.floor(rate * 10000)
end

---构建结构化日志 payload，不直接写磁盘。
---该方法用于保证 Java ingest 的解析字段稳定。
function _M.build_payload(runtime)
    if not runtime then
        return nil
    end

    local ctx = runtime.context or {}
    local decision = runtime.decision or {}
    local signals = runtime.signals or {}

    return {
        event_id = ctx.request_id,
        event_time = now_utc_iso8601(),
        mode = decision.mode or ctx.mode,
        method = ctx.method,
        route_key = ctx.route_key,
        host = ctx.host,
        content_type = ctx.content_type,
        content_length = ctx.content_length,
        surface = ctx.surface,
        field_name = ctx.field_name,
        json_path = ctx.json_path,
        body_inspected = ctx.body_inspected == true,
        body_skip_reason = ctx.body_skip_reason,
        detector = signals.detector or ctx.detector,
        detector_signature = signals.detector_signature or ctx.detector_signature,
        pattern_key = ctx.pattern_key,
        pattern_key_hash = ctx.pattern_key_hash,
        client_ip = ctx.client_ip,
        user_agent_hash = ctx.user_agent_hash,
        matched_value = ctx.matched_value,
        normalized_sqli_value = signals.normalized_sqli_value,
        normalized_xss_value = signals.normalized_xss_value,
        model_sqli_input = signals.model_sqli_input,
        model_xss_input = signals.model_xss_input,
        model_input_truncated = signals.model_input_truncated == true,
        invalid_utf8 = signals.invalid_utf8 == true,
        libinjection_required = signals.libinjection_required == true,
        libinjection_available = signals.libinjection_available == true,
        libinjection_backend = signals.libinjection_backend,
        libinjection_load_error = signals.libinjection_load_error,
        detector_unavailable = signals.detector_unavailable == true,
        decision_candidate = decision.decision_candidate,
        final_action = decision.final_action,
        enforced_action = decision.enforced_action,
        policy_decision_basis = decision.policy_decision_basis,
        threat_classification = decision.threat_classification,
        alert_level = decision.alert_level,
        timeout_stage = decision.timeout_stage,
        budget_exhausted = decision.budget_exhausted == true,
        elapsed_ms = decision.elapsed_ms,
        hard_timeout_ms = decision.hard_timeout_ms,
        normalization_profile = signals.normalization_profile or "norm-v1",
        exemption_applied = signals.exemption_applied == true,
        exemption_id = signals.exemption_id,
        exemption_match_scope = signals.exemption_match_scope or "",
        exemption_match_key = signals.exemption_match_key or "",
        scope_relaxation_applied = signals.exemption_match_scope == "detector_field",
        exemptions_generation = signals.exemptions_generation or 0,
        pattern_state = signals.pattern_state or "unknown",
        candidate_status = signals.candidate_status or "",
        blacklist_key = signals.reputation_blacklist_key,
        blacklist_hit = signals.reputation_blacklist_hit == true,
        reputation_score = signals.reputation_score,
        weak_signal_score = signals.weak_signal_score,
        sgd_score = signals.sgd_score,
        sgd_score_raw = signals.sgd_score_raw,
        sgd_score_used = decision.sgd_score_used,
        sgd_decision_weight = decision.sgd_decision_weight,
        sgd_backend = signals.sgd_backend,
        sgd_model_state = signals.sgd_model_state,
        sgd_model_load_state = signals.sgd_model_load_state,
        model_version = signals.model_version,
        status_code = ngx.status
    }
end

---编码日志并返回不同日志通道的落盘决策。
---@param runtime table
---@param cfg table
---@return table|nil
function _M.emit(runtime, cfg)
    local payload = _M.build_payload(runtime)
    if not payload then
        return nil
    end

    local encoded = cjson.encode(payload)
    if not encoded then
        return nil
    end

    local log_cfg = cfg or {}
    return {
        encoded = encoded,
        payload = payload,
        alert_loggable = is_alert(payload),
        sample_loggable = should_sample(payload, log_cfg.sample_rate),
        trace_loggable = log_cfg.trace_enabled == true
    }
end

return _M
