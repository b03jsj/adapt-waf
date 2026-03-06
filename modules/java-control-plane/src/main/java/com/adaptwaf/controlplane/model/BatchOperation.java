package com.adaptwaf.controlplane.model;

import java.time.Instant;

/**
 * 批量审核任务模型。
 */
public record BatchOperation(
        String operationId,
        String operationType,
        String status,
        String operator,
        String reason,
        String ticketId,
        String requestedScope,
        String requestedPatternState,
        int totalCount,
        int successCount,
        int failedCount,
        Instant createdAt,
        Instant updatedAt
) {
}
