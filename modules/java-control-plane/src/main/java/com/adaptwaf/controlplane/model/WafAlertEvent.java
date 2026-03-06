package com.adaptwaf.controlplane.model;

import java.time.Instant;

/**
 * 告警事件模型，对应 {@code waf_alert_event} 表的核心字段。
 */
public record WafAlertEvent(
        String eventId,
        Instant eventTime,
        String method,
        String routeKey,
        String contentType,
        String surface,
        String fieldName,
        String jsonPath,
        String detector,
        String detectorSignature,
        String patternKey,
        String patternKeyHash,
        String alertLevel,
        String finalAction,
        String policyDecisionBasis,
        boolean firstSeenPattern,
        boolean exemptionApplied,
        String exemptionId,
        String exemptionMatchScope,
        int statusCode,
        String clientIp,
        String userAgentHash,
        String normalizationProfile,
        String payloadJson
) {
}
