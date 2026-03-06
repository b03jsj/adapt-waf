package com.adaptwaf.controlplane.model;

import java.time.Instant;

/**
 * 发布任务记录模型。
 */
public record PublishRecord(
        String publishId,
        long generation,
        String sha256,
        String operator,
        String reason,
        String status,
        Instant createdAt,
        Instant updatedAt
) {
}
