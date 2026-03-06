package com.adaptwaf.controlplane.model;

import java.time.Instant;

/**
 * 豁免候选记录模型。
 */
public record ExemptionCandidate(
        long candidateId,
        String patternKey,
        String candidateStatus,
        String candidateReason,
        String metricsSnapshotJson,
        Instant createdAt,
        Instant updatedAt
) {
}
