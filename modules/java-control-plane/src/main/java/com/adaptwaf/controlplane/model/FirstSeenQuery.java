package com.adaptwaf.controlplane.model;

import java.time.Instant;

/**
 * first-seen 队列筛选条件。
 */
public record FirstSeenQuery(
        String routeKey,
        String detector,
        String method,
        String contentType,
        String surface,
        String alertLevel,
        Instant fromTime,
        Instant toTime
) {
}
