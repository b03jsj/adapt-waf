package com.adaptwaf.controlplane.model;

import java.time.Instant;

/**
 * first-seen 审核队列事件模型。
 */
public record FirstSeenEvent(
        String eventId,
        Instant eventTime,
        String routeKey,
        String method,
        String contentType,
        String surface,
        String fieldName,
        String jsonPath,
        String detector,
        String detectorSignature,
        String patternKey,
        String alertLevel,
        String finalAction,
        String policyDecisionBasis
) {
}
