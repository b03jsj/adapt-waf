package com.adaptwaf.controlplane.model;

import java.time.Instant;

/**
 * 审核审计记录模型。
 */
public record ReviewAuditRecord(
        long auditId,
        String operator,
        String action,
        String targetType,
        String targetId,
        String beforeJson,
        String afterJson,
        String reason,
        String ticketId,
        Instant createdAt
) {
}
