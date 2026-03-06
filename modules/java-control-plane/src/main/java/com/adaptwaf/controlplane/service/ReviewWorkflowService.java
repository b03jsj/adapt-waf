package com.adaptwaf.controlplane.service;

import com.adaptwaf.controlplane.model.ExemptionCandidate;
import com.adaptwaf.controlplane.model.FirstSeenEvent;
import com.adaptwaf.controlplane.model.FirstSeenQuery;
import com.adaptwaf.controlplane.model.CandidateQuery;
import com.adaptwaf.controlplane.model.ReviewAuditRecord;
import com.adaptwaf.controlplane.repository.AlertEventRepository;
import com.adaptwaf.controlplane.repository.CandidateRepository;
import com.adaptwaf.controlplane.repository.ExemptionRepository;
import com.adaptwaf.controlplane.repository.PatternStateRepository;
import com.adaptwaf.controlplane.repository.ReviewAuditRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 审核工作流服务。
 */
public class ReviewWorkflowService {

    private final AlertEventRepository alertEventRepository;
    private final CandidateRepository candidateRepository;
    private final ExemptionRepository exemptionRepository;
    private final PatternStateRepository patternStateRepository;
    private final ReviewAuditRepository reviewAuditRepository;
    private final ObjectMapper objectMapper;

    public ReviewWorkflowService(
            AlertEventRepository alertEventRepository,
            CandidateRepository candidateRepository,
            ExemptionRepository exemptionRepository,
            PatternStateRepository patternStateRepository,
            ReviewAuditRepository reviewAuditRepository,
            ObjectMapper objectMapper
    ) {
        this.alertEventRepository = alertEventRepository;
        this.candidateRepository = candidateRepository;
        this.exemptionRepository = exemptionRepository;
        this.patternStateRepository = patternStateRepository;
        this.reviewAuditRepository = reviewAuditRepository;
        this.objectMapper = objectMapper;
    }

    /**
     * 查询 first-seen 队列。
     *
     * @param limit 限制条数
     * @param offset 偏移量
     * @return 事件列表
     */
    public List<FirstSeenEvent> listFirstSeenQueue(int limit, int offset) {
        return alertEventRepository.listFirstSeenQueue(limit, offset);
    }

    /**
     * 按筛选条件查询 first-seen 队列。
     *
     * @param query 筛选条件
     * @param limit 限制条数
     * @param offset 偏移量
     * @return 事件列表
     */
    public List<FirstSeenEvent> listFirstSeenQueue(FirstSeenQuery query, int limit, int offset) {
        return alertEventRepository.listFirstSeenQueue(query, limit, offset);
    }

    /**
     * 统计 first-seen 队列总量。
     *
     * @param query 条件
     * @return 总量
     */
    public long countFirstSeenQueue(FirstSeenQuery query) {
        return alertEventRepository.countFirstSeenQueue(query);
    }

    /**
     * 查询候选列表。
     *
     * @param status 状态
     * @param limit 条数
     * @param offset 偏移
     * @return 候选列表
     */
    public List<ExemptionCandidate> listCandidates(String status, int limit, int offset) {
        return candidateRepository.listByStatus(status, limit, offset);
    }

    /**
     * 按筛选条件查询候选列表。
     *
     * @param query 条件
     * @param limit 限制条数
     * @param offset 偏移
     * @return 候选列表
     */
    public List<ExemptionCandidate> listCandidates(CandidateQuery query, int limit, int offset) {
        return candidateRepository.list(query, limit, offset);
    }

    /**
     * 统计候选总量。
     *
     * @param query 条件
     * @return 总量
     */
    public long countCandidates(CandidateQuery query) {
        return candidateRepository.count(query);
    }

    /**
     * 查询审计日志。
     *
     * @param limit 条数
     * @param offset 偏移
     * @return 审计记录
     */
    public List<ReviewAuditRecord> listAudit(int limit, int offset) {
        return reviewAuditRepository.list(limit, offset);
    }

    /**
     * 统计审计记录总量。
     *
     * @return 总量
     */
    public long countAudit() {
        return reviewAuditRepository.count();
    }

    /**
     * 审批通过候选并落地豁免规则。
     *
     * @param candidateId 候选 ID
     * @param operator 操作人
     * @param reason 审批原因
     * @param ticketId 工单号
     * @param requestedScope 指定 scope（为空则默认 signature_exact）
     * @param expiresAt 指定过期时间（ISO-8601，可为空）
     * @return 审批结果
     */
    public ApprovalResult approveCandidate(
            long candidateId,
            String operator,
            String reason,
            String ticketId,
            String requestedScope,
            String expiresAt
    ) {
        ExemptionCandidate candidate = candidateRepository.findById(candidateId);
        if (candidate == null) {
            throw new IllegalArgumentException("candidate_not_found:" + candidateId);
        }
        if (!"auto_suggested".equals(candidate.candidateStatus())) {
            throw new IllegalArgumentException("candidate_status_invalid:" + candidate.candidateStatus());
        }

        boolean casOk = candidateRepository.compareAndSetStatus(candidateId, "auto_suggested", "approved");
        if (!casOk) {
            throw new IllegalStateException("candidate_status_conflict:" + candidateId);
        }

        PatternKeyService.PatternKeyParts parts = PatternKeyService.parsePatternKeyV1(candidate.patternKey());
        String matchScope = normalizeScope(requestedScope);
        validateScope(matchScope, parts.detector());
        String finalExpiresAt = normalizeExpiresAt(matchScope, expiresAt);

        String exemptionId = "exm_" + UUID.randomUUID().toString().replace("-", "");
        Map<String, Object> rule = buildExemptionRule(
                exemptionId,
                parts,
                matchScope,
                reason,
                operator,
                finalExpiresAt
        );

        try {
            exemptionRepository.insertRule(rule);
            patternStateRepository.updatePatternState(candidate.patternKey(), "benign_confirmed");
            reviewAuditRepository.append(
                    safe(operator, "unknown"),
                    "candidate_approve",
                    "waf_exemption_candidate",
                    Long.toString(candidateId),
                    candidateToJson(candidate),
                    objectMapper.writeValueAsString(Map.of(
                            "candidate_status", "approved",
                            "exemption_id", exemptionId,
                            "match_scope", matchScope
                    )),
                    safe(reason, "approved"),
                    ticketId
            );
            return new ApprovalResult(candidateId, exemptionId, matchScope);
        } catch (Exception e) {
            // 失败回滚候选状态，避免卡在 approved 但无规则。
            candidateRepository.compareAndSetStatus(candidateId, "approved", "auto_suggested");
            throw new IllegalStateException("candidate_approve_failed", e);
        }
    }

    /**
     * 审批拒绝候选。
     *
     * @param candidateId 候选 ID
     * @param operator 操作人
     * @param reason 拒绝原因
     * @param ticketId 工单号
     * @param patternStateReject 拒绝后状态（unknown/attack_confirmed）
     */
    public void rejectCandidate(
            long candidateId,
            String operator,
            String reason,
            String ticketId,
            String patternStateReject
    ) {
        ExemptionCandidate candidate = candidateRepository.findById(candidateId);
        if (candidate == null) {
            throw new IllegalArgumentException("candidate_not_found:" + candidateId);
        }
        if (!"auto_suggested".equals(candidate.candidateStatus())) {
            throw new IllegalArgumentException("candidate_status_invalid:" + candidate.candidateStatus());
        }

        boolean casOk = candidateRepository.compareAndSetStatus(candidateId, "auto_suggested", "rejected");
        if (!casOk) {
            throw new IllegalStateException("candidate_status_conflict:" + candidateId);
        }

        String normalizedState = normalizeRejectState(patternStateReject);
        if (!"unknown".equals(normalizedState)) {
            patternStateRepository.updatePatternState(candidate.patternKey(), normalizedState);
        }

        reviewAuditRepository.append(
                safe(operator, "unknown"),
                "candidate_reject",
                "waf_exemption_candidate",
                Long.toString(candidateId),
                candidateToJson(candidate),
                toJson(Map.of("candidate_status", "rejected", "pattern_state", normalizedState)),
                safe(reason, "rejected"),
                ticketId
        );
    }

    private Map<String, Object> buildExemptionRule(
            String exemptionId,
            PatternKeyService.PatternKeyParts parts,
            String matchScope,
            String reason,
            String operator,
            String expiresAt
    ) {
        Map<String, Object> rule = new HashMap<>();
        rule.put("id", exemptionId);
        rule.put("enabled", true);
        rule.put("match_scope", matchScope);
        rule.put("detector", parts.detector());
        rule.put("signature", parts.signatureToken());
        rule.put("method", parts.method());
        rule.put("route_key", parts.routeKey());
        rule.put("content_type", parts.contentType());
        rule.put("surface", parts.surface());
        rule.put("field_name", parts.fieldName());
        rule.put("json_path", parts.jsonPath());
        rule.put("action", "allow_log");
        rule.put("reason", safe(reason, "confirmed_false_positive"));
        rule.put("owner", safe(operator, "unknown"));
        rule.put("source_event_ids", List.of());
        rule.put("created_at", Instant.now().toString());
        rule.put("expires_at", expiresAt);
        return rule;
    }

    private String normalizeScope(String requestedScope) {
        if (requestedScope == null || requestedScope.isBlank()) {
            return "signature_exact";
        }
        if (!"signature_exact".equals(requestedScope) && !"detector_field".equals(requestedScope)) {
            throw new IllegalArgumentException("invalid_match_scope:" + requestedScope);
        }
        return requestedScope;
    }

    private void validateScope(String scope, String detector) {
        if ("detector_field".equals(scope)
                && !"libinjection_sqli".equals(detector)
                && !"libinjection_xss".equals(detector)) {
            throw new IllegalArgumentException("detector_scope_not_allowed:" + detector);
        }
    }

    private String normalizeExpiresAt(String scope, String expiresAt) {
        if (!"detector_field".equals(scope)) {
            return null;
        }
        if (expiresAt != null && !expiresAt.isBlank()) {
            return expiresAt;
        }
        return Instant.now().plus(30, ChronoUnit.DAYS).toString();
    }

    private String normalizeRejectState(String state) {
        if (state == null || state.isBlank()) {
            return "unknown";
        }
        if ("unknown".equals(state) || "attack_confirmed".equals(state)) {
            return state;
        }
        throw new IllegalArgumentException("invalid_pattern_state:" + state);
    }

    private String candidateToJson(ExemptionCandidate candidate) {
        return toJson(Map.of(
                "candidate_id", candidate.candidateId(),
                "pattern_key", candidate.patternKey(),
                "candidate_status", candidate.candidateStatus(),
                "candidate_reason", candidate.candidateReason()
        ));
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private String safe(String value, String fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return value;
    }

    /**
     * 候选审批结果。
     *
     * @param candidateId 候选 ID
     * @param exemptionId 生成的豁免 ID
     * @param matchScope 生效匹配范围
     */
    public record ApprovalResult(long candidateId, String exemptionId, String matchScope) {
    }
}
