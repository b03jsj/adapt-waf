package com.adaptwaf.controlplane.model;

import java.time.Instant;

/**
 * 批量审核任务明细模型。
 */
public record BatchOperationItem(
        long id,
        String operationId,
        long candidateId,
        boolean success,
        String exemptionId,
        String matchScope,
        String error,
        Instant createdAt
) {
}
