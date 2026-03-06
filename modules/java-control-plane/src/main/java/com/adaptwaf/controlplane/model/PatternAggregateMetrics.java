package com.adaptwaf.controlplane.model;

import java.util.Map;

/**
 * 模式聚合统计结果。
 */
public record PatternAggregateMetrics(
        String patternKey,
        long hits,
        double ratio2xx,
        int uniqueIp,
        double singleIpRatio,
        int activeDays,
        double peakDayRatio,
        Map<String, Long> ipHitCount
) {
}
