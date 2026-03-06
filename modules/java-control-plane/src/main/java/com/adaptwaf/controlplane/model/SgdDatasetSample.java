package com.adaptwaf.controlplane.model;

import java.time.Instant;

/**
 * SGD 训练样本记录。
 */
public record SgdDatasetSample(
        String attackType,
        int label,
        String text,
        String source,
        String eventId,
        Instant eventTime,
        String routeKey,
        String fieldName,
        String detector,
        String normalizationProfile
) {
}
