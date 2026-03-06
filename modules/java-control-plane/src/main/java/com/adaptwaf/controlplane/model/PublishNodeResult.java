package com.adaptwaf.controlplane.model;

import java.time.Instant;

/**
 * 发布节点结果视图模型。
 */
public record PublishNodeResult(
        String publishId,
        String nodeId,
        String nodeStatus,
        long currentGeneration,
        String lastError,
        Instant updatedAt
) {
}
