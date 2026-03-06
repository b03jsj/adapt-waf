package com.adaptwaf.controlplane.service;

import java.util.Locale;

/**
 * {@code pattern_key_v1} 构造服务。
 */
public final class PatternKeyService {

    private static final String SEP = "|";

    private PatternKeyService() {
    }

    /**
     * 生成 {@code pattern_key_v1}。
     * 格式：method|route_key|content_type|surface|field_selector|detector|signature_token
     *
     * @param method HTTP 方法
     * @param routeKey 路由键
     * @param contentType 归一化 Content-Type
     * @param surface 输入面
     * @param fieldName 字段名
     * @param jsonPath JSON 路径
     * @param detector 检测器
     * @param signatureToken 指纹标识
     * @return pattern_key_v1
     */
    public static String buildPatternKeyV1(
            String method,
            String routeKey,
            String contentType,
            String surface,
            String fieldName,
            String jsonPath,
            String detector,
            String signatureToken
    ) {
        String normalizedMethod = safeUpper(method);
        String normalizedSurface = safe(surface);
        String fieldSelector = "json".equals(normalizedSurface) ? safe(jsonPath) : safe(fieldName);
        if ("-".equals(fieldSelector)) {
            fieldSelector = safe(fieldName);
        }

        return String.join(
                SEP,
                escapePipe(normalizedMethod),
                escapePipe(safe(routeKey)),
                escapePipe(safe(contentType)),
                escapePipe(normalizedSurface),
                escapePipe(fieldSelector),
                escapePipe(safe(detector)),
                escapePipe(safe(signatureToken))
        );
    }

    /**
     * 解析 {@code pattern_key_v1} 为结构化字段。
     *
     * @param patternKey 模式键文本
     * @return 解析结果
     */
    public static PatternKeyParts parsePatternKeyV1(String patternKey) {
        String[] parts = (patternKey == null ? "" : patternKey).split("\\|", -1);
        if (parts.length != 7) {
            throw new IllegalArgumentException("invalid_pattern_key_v1:" + patternKey);
        }

        String method = safeUpper(unescapePipe(parts[0]));
        String routeKey = safe(unescapePipe(parts[1]));
        String contentType = safe(unescapePipe(parts[2])).toLowerCase(Locale.ROOT);
        String surface = safe(unescapePipe(parts[3]));
        String fieldSelector = safe(unescapePipe(parts[4]));
        String detector = safe(unescapePipe(parts[5]));
        String signatureToken = safe(unescapePipe(parts[6]));

        String fieldName = "-";
        String jsonPath = "-";
        if ("json".equals(surface)) {
            jsonPath = fieldSelector;
        } else {
            fieldName = fieldSelector;
        }

        return new PatternKeyParts(
                method,
                routeKey,
                contentType,
                surface,
                fieldName,
                jsonPath,
                detector,
                signatureToken
        );
    }

    private static String safe(String value) {
        if (value == null || value.isBlank()) {
            return "-";
        }
        return value;
    }

    private static String safeUpper(String value) {
        return safe(value).toUpperCase(Locale.ROOT);
    }

    private static String escapePipe(String value) {
        return value.replace("|", "%7C");
    }

    private static String unescapePipe(String value) {
        return value.replace("%7C", "|");
    }

    /**
     * {@code pattern_key_v1} 字段结构。
     *
     * @param method HTTP 方法
     * @param routeKey 路由键
     * @param contentType 归一化 Content-Type
     * @param surface 输入面
     * @param fieldName 字段名（json 面为 "-"）
     * @param jsonPath JSON 路径（非 json 面为 "-"）
     * @param detector 检测器
     * @param signatureToken 指纹
     */
    public record PatternKeyParts(
            String method,
            String routeKey,
            String contentType,
            String surface,
            String fieldName,
            String jsonPath,
            String detector,
            String signatureToken
    ) {
    }
}
