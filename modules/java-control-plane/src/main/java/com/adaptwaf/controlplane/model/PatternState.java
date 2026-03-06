package com.adaptwaf.controlplane.model;

import java.time.Instant;

/**
 * 模式状态模型，对应 {@code waf_pattern_state}。
 */
public record PatternState(
        String patternKey,
        String patternState,
        Instant firstSeen,
        Instant lastSeen,
        long hitCount,
        String lastDecision
) {
}
