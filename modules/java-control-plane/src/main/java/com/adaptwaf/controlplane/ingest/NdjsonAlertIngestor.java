package com.adaptwaf.controlplane.ingest;

import com.adaptwaf.controlplane.model.WafAlertEvent;
import com.adaptwaf.controlplane.repository.AlertEventRepository;
import com.adaptwaf.controlplane.repository.PatternStateRepository;
import com.adaptwaf.controlplane.service.PatternKeyService;
import com.adaptwaf.controlplane.util.HashUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * NDJSON 告警日志入库编排器。
 */
public class NdjsonAlertIngestor {

    private static final DateTimeFormatter NGINX_UTC_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final ObjectMapper objectMapper;
    private final AlertEventRepository alertEventRepository;
    private final PatternStateRepository patternStateRepository;

    public NdjsonAlertIngestor(
            ObjectMapper objectMapper,
            AlertEventRepository alertEventRepository,
            PatternStateRepository patternStateRepository
    ) {
        this.objectMapper = objectMapper;
        this.alertEventRepository = alertEventRepository;
        this.patternStateRepository = patternStateRepository;
    }

    /**
     * 批量处理 NDJSON 行数据。
     *
     * @param lines 原始日志行
     * @throws Exception 解析或入库异常
     */
    public void ingestLines(List<String> lines) throws Exception {
        List<WafAlertEvent> events = new ArrayList<>(lines.size());
        for (String line : lines) {
            if (line == null || line.isBlank()) {
                continue;
            }
            WafAlertEvent event = parse(line);
            boolean firstSeen = patternStateRepository.upsertAndCheckFirstSeen(
                    event.patternKey(),
                    event.eventTime(),
                    event.policyDecisionBasis()
            );
            events.add(overrideFirstSeen(event, firstSeen));
        }
        if (!events.isEmpty()) {
            alertEventRepository.saveBatch(events);
        }
    }

    private WafAlertEvent parse(String line) throws Exception {
        JsonNode node = objectMapper.readTree(line);
        String method = text(node, "method", "GET");
        String routeKey = text(node, "route_key", "-");
        String contentType = text(node, "content_type", "-");
        String surface = text(node, "surface", "-");
        String fieldName = text(node, "field_name", "-");
        String jsonPath = text(node, "json_path", "-");
        String detector = text(node, "detector", "-");
        String signature = text(node, "detector_signature", "-");

        String patternKey = text(node, "pattern_key", "");
        if (patternKey.isBlank()) {
            patternKey = PatternKeyService.buildPatternKeyV1(
                    method,
                    routeKey,
                    contentType,
                    surface,
                    fieldName,
                    jsonPath,
                    detector,
                    signature
            );
        }
        String patternKeyHash = text(node, "pattern_key_hash", "");
        if (patternKeyHash.isBlank()) {
            patternKeyHash = HashUtils.sha256Hex(patternKey.getBytes(StandardCharsets.UTF_8));
        }

        String timeText = text(node, "event_time", Instant.now().toString());
        Instant eventTime = parseEventTime(timeText);

        return new WafAlertEvent(
                text(node, "event_id", "evt-" + System.nanoTime()),
                eventTime,
                method,
                routeKey,
                contentType,
                surface,
                fieldName,
                jsonPath,
                detector,
                signature,
                patternKey,
                patternKeyHash,
                text(node, "alert_level", "info"),
                text(node, "final_action", "allow"),
                text(node, "policy_decision_basis", "none"),
                false,
                bool(node, "exemption_applied", false),
                text(node, "exemption_id", null),
                text(node, "exemption_match_scope", null),
                node.path("status_code").asInt(0),
                text(node, "client_ip", "-"),
                text(node, "user_agent_hash", "-"),
                text(node, "normalization_profile", "norm-v1"),
                line
        );
    }

    private static WafAlertEvent overrideFirstSeen(WafAlertEvent event, boolean firstSeen) {
        String payload = event.payloadJson();
        if (payload != null && payload.endsWith("}") && !payload.contains("\"first_seen_pattern\"")) {
            payload = payload.substring(0, payload.length() - 1) + ",\"first_seen_pattern\":" + firstSeen + "}";
        }
        return new WafAlertEvent(
                event.eventId(),
                event.eventTime(),
                event.method(),
                event.routeKey(),
                event.contentType(),
                event.surface(),
                event.fieldName(),
                event.jsonPath(),
                event.detector(),
                event.detectorSignature(),
                event.patternKey(),
                event.patternKeyHash(),
                event.alertLevel(),
                event.finalAction(),
                event.policyDecisionBasis(),
                firstSeen,
                event.exemptionApplied(),
                event.exemptionId(),
                event.exemptionMatchScope(),
                event.statusCode(),
                event.clientIp(),
                event.userAgentHash(),
                event.normalizationProfile(),
                payload
        );
    }

    private static String text(JsonNode node, String key, String defaultValue) {
        JsonNode value = node.get(key);
        if (value == null || value.isNull()) {
            return defaultValue;
        }
        String v = value.asText();
        return (v == null || v.isBlank()) ? defaultValue : v;
    }

    private static boolean bool(JsonNode node, String key, boolean defaultValue) {
        JsonNode value = node.get(key);
        if (value == null || value.isNull()) {
            return defaultValue;
        }
        if (value.isBoolean()) {
            return value.asBoolean();
        }
        String text = value.asText();
        if (text == null || text.isBlank()) {
            return defaultValue;
        }
        String lowered = text.trim().toLowerCase();
        if ("1".equals(lowered) || "true".equals(lowered) || "yes".equals(lowered) || "on".equals(lowered)) {
            return true;
        }
        if ("0".equals(lowered) || "false".equals(lowered) || "no".equals(lowered) || "off".equals(lowered)) {
            return false;
        }
        return defaultValue;
    }

    /**
     * 解析日志时间，兼容 ISO-8601 与 Nginx 常见 UTC 文本格式。
     *
     * @param rawTime 原始时间字符串
     * @return 解析后的 UTC 时间
     */
    private static Instant parseEventTime(String rawTime) {
        try {
            return Instant.parse(rawTime);
        } catch (Exception ignored) {
            // 忽略并降级到 Nginx 文本时间解析。
        }

        try {
            LocalDateTime localDateTime = LocalDateTime.parse(rawTime, NGINX_UTC_FORMAT);
            return localDateTime.toInstant(ZoneOffset.UTC);
        } catch (Exception ignored) {
            // 忽略并返回当前时间，避免入库流程中断。
        }

        return Instant.now();
    }
}
