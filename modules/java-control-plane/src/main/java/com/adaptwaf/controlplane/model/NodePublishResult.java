package com.adaptwaf.controlplane.model;

/**
 * 单节点发布结果。
 */
public record NodePublishResult(
        String nodeId,
        boolean success,
        long currentGeneration,
        String lastError
) {
}
