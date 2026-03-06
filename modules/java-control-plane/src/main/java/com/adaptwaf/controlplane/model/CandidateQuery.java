package com.adaptwaf.controlplane.model;

import java.time.Instant;

/**
 * 候选列表筛选条件。
 */
public record CandidateQuery(
        String status,
        String reasonLike,
        String patternKeyLike,
        Instant updatedFrom,
        Instant updatedTo
) {
}
