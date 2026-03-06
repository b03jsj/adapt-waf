package com.adaptwaf.controlplane.service;

import com.adaptwaf.controlplane.config.ControlPlaneConfig;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * SGD 模型发布门禁服务。
 * <p>
 * 目标：把 {@code candidate -> shadow_observe -> stable} 做成可执行流程，
 * 避免只停留在文档约定。
 */
public class SgdReleaseGateService {

    private static final Set<String> VALID_MODEL_STATES = Set.of("candidate", "shadow_observe", "stable");

    private final ObjectMapper objectMapper;
    private final ControlPlaneConfig config;

    public SgdReleaseGateService(ObjectMapper objectMapper, ControlPlaneConfig config) {
        this.objectMapper = objectMapper;
        this.config = config;
    }

    /**
     * 读取 manifest 当前状态。
     *
     * @param manifestPath manifest 路径
     * @return 状态摘要
     * @throws Exception 读写异常
     */
    public ModelStateSummary show(Path manifestPath) throws Exception {
        ObjectNode manifest = readManifest(manifestPath);
        return toSummary(manifestPath, manifest);
    }

    /**
     * 手工设置模型状态。
     *
     * @param manifestPath manifest 路径
     * @param targetState 目标状态
     * @return 更新后状态
     * @throws Exception 读写异常
     */
    public ModelStateSummary setModelState(Path manifestPath, String targetState) throws Exception {
        String normalizedTargetState = normalizeModelState(targetState);
        if (!VALID_MODEL_STATES.contains(normalizedTargetState)) {
            throw new IllegalArgumentException("invalid_model_state:" + targetState);
        }

        ObjectNode manifest = readManifest(manifestPath);
        manifest.put("model_state", normalizedTargetState);
        writeManifestAtomic(manifestPath, manifest);
        return toSummary(manifestPath, manifest);
    }

    /**
     * 执行离线门禁并在通过后晋级到 shadow_observe。
     *
     * @param manifestPath manifest 路径
     * @param offlineMetricsReport 离线评估报告
     * @return 门禁结果
     * @throws Exception 读写异常
     */
    public GateResult promoteToShadowObserve(Path manifestPath, Path offlineMetricsReport) throws Exception {
        ObjectNode manifest = readManifest(manifestPath);
        String currentState = normalizeModelState(stringValue(manifest, "model_state", "candidate"));
        List<String> failedChecks = new ArrayList<>();

        if (!"candidate".equals(currentState)) {
            failedChecks.add("current_state_not_candidate");
        }

        JsonNode report = readReport(offlineMetricsReport);
        long positiveSamples = longValue(report, "positive_samples", -1);
        long negativeSamples = longValue(report, "negative_samples", -1);
        long hardNegativeSamples = longValue(report, "hard_negative_samples", -1);
        double precisionAtAssist = doubleValue(report, "precision_at_assist_threshold", -1);
        double cleanFpr = doubleValue(report, "clean_false_positive_rate", -1);
        double hardNegativeFpr = doubleValue(report, "hard_negative_false_positive_rate", -1);

        if (positiveSamples < config.sgdGateMinPositiveSamples()) {
            failedChecks.add("positive_samples_too_low");
        }
        if (negativeSamples < config.sgdGateMinNegativeSamples()) {
            failedChecks.add("negative_samples_too_low");
        }
        if (hardNegativeSamples < config.sgdGateMinHardNegativeSamples()) {
            failedChecks.add("hard_negative_samples_too_low");
        }
        if (precisionAtAssist < config.sgdGateMinPrecisionAtAssistThreshold()) {
            failedChecks.add("precision_at_assist_threshold_too_low");
        }
        if (cleanFpr < 0 || cleanFpr > config.sgdGateMaxCleanFalsePositiveRate()) {
            failedChecks.add("clean_false_positive_rate_too_high");
        }
        if (hardNegativeFpr < 0 || hardNegativeFpr > config.sgdGateMaxHardNegativeFalsePositiveRate()) {
            failedChecks.add("hard_negative_false_positive_rate_too_high");
        }

        boolean passed = failedChecks.isEmpty();
        if (passed) {
            manifest.put("model_state", "shadow_observe");
            writeManifestAtomic(manifestPath, manifest);
        }

        return new GateResult(
                passed,
                currentState,
                passed ? "shadow_observe" : currentState,
                failedChecks,
                toSummary(manifestPath, manifest)
        );
    }

    /**
     * 执行影子期门禁并在通过后晋级到 stable。
     *
     * @param manifestPath manifest 路径
     * @param shadowMetricsReport 影子期评估报告
     * @return 门禁结果
     * @throws Exception 读写异常
     */
    public GateResult promoteToStable(Path manifestPath, Path shadowMetricsReport) throws Exception {
        ObjectNode manifest = readManifest(manifestPath);
        String currentState = normalizeModelState(stringValue(manifest, "model_state", "candidate"));
        List<String> failedChecks = new ArrayList<>();

        if (!"shadow_observe".equals(currentState)) {
            failedChecks.add("current_state_not_shadow_observe");
        }

        JsonNode report = readReport(shadowMetricsReport);
        long observeHours = longValue(report, "observe_hours", -1);
        double falsePositiveRate = doubleValue(report, "false_positive_rate", -1);
        double regressionDelta = doubleValue(report, "regression_delta", -1);

        if (observeHours < config.sgdGateShadowObserveMinHours()) {
            failedChecks.add("observe_hours_too_low");
        }
        if (falsePositiveRate < 0 || falsePositiveRate > config.sgdGateShadowMaxFalsePositiveRate()) {
            failedChecks.add("shadow_false_positive_rate_too_high");
        }
        if (regressionDelta < 0 || regressionDelta > config.sgdGateShadowMaxRegressionDelta()) {
            failedChecks.add("shadow_regression_delta_too_high");
        }

        boolean passed = failedChecks.isEmpty();
        if (passed) {
            manifest.put("model_state", "stable");
            writeManifestAtomic(manifestPath, manifest);
        }

        return new GateResult(
                passed,
                currentState,
                passed ? "stable" : currentState,
                failedChecks,
                toSummary(manifestPath, manifest)
        );
    }

    private ObjectNode readManifest(Path manifestPath) throws Exception {
        if (manifestPath == null || !Files.exists(manifestPath)) {
            throw new IllegalArgumentException("manifest_not_found:" + manifestPath);
        }
        JsonNode root = objectMapper.readTree(Files.readString(manifestPath, StandardCharsets.UTF_8));
        if (!(root instanceof ObjectNode objectNode)) {
            throw new IllegalStateException("manifest_not_object");
        }

        String format = stringValue(objectNode, "format", "");
        if (!"sgd-linear-v1".equals(format)) {
            throw new IllegalStateException("manifest_format_invalid:" + format);
        }
        String attackType = stringValue(objectNode, "attack_type", "");
        if (!"sqli".equals(attackType) && !"xss".equals(attackType)) {
            throw new IllegalStateException("manifest_attack_type_invalid:" + attackType);
        }
        return objectNode;
    }

    private JsonNode readReport(Path reportPath) throws Exception {
        if (reportPath == null || !Files.exists(reportPath)) {
            throw new IllegalArgumentException("report_not_found:" + reportPath);
        }
        return objectMapper.readTree(Files.readString(reportPath, StandardCharsets.UTF_8));
    }

    private ModelStateSummary toSummary(Path manifestPath, ObjectNode manifest) {
        return new ModelStateSummary(
                stringValue(manifest, "attack_type", "-"),
                stringValue(manifest, "model_version", "-"),
                normalizeModelState(stringValue(manifest, "model_state", "candidate")),
                stringValue(manifest, "normalization_profile", "-"),
                manifestPath
        );
    }

    private void writeManifestAtomic(Path manifestPath, ObjectNode manifest) throws IOException {
        Path parent = manifestPath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path tmpPath = manifestPath.resolveSibling(
                manifestPath.getFileName() + ".tmp." + System.currentTimeMillis()
        );
        String prettyJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(manifest);
        Files.writeString(
                tmpPath,
                prettyJson,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE
        );

        try {
            Files.move(tmpPath, manifestPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException ignored) {
            Files.move(tmpPath, manifestPath, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static String normalizeModelState(String state) {
        if (state == null || state.isBlank()) {
            return "candidate";
        }
        return state.trim().toLowerCase(Locale.ROOT);
    }

    private static String stringValue(ObjectNode node, String key, String defaultValue) {
        JsonNode value = node.get(key);
        if (value == null || value.isNull()) {
            return defaultValue;
        }
        String text = value.asText();
        if (text == null || text.isBlank()) {
            return defaultValue;
        }
        return text;
    }

    private static long longValue(JsonNode node, String key, long defaultValue) {
        if (node == null || node.get(key) == null || node.get(key).isNull()) {
            return defaultValue;
        }
        return node.get(key).asLong(defaultValue);
    }

    private static double doubleValue(JsonNode node, String key, double defaultValue) {
        if (node == null || node.get(key) == null || node.get(key).isNull()) {
            return defaultValue;
        }
        return node.get(key).asDouble(defaultValue);
    }

    /**
     * Manifest 状态摘要。
     *
     * @param attackType 攻击类型
     * @param modelVersion 模型版本
     * @param modelState 发布状态
     * @param normalizationProfile 规范化配置
     * @param manifestPath manifest 文件路径
     */
    public record ModelStateSummary(
            String attackType,
            String modelVersion,
            String modelState,
            String normalizationProfile,
            Path manifestPath
    ) {
    }

    /**
     * 门禁执行结果。
     *
     * @param passed 是否通过
     * @param fromState 门禁前状态
     * @param toState 门禁后状态
     * @param failedChecks 未通过项
     * @param summary 当前 manifest 摘要
     */
    public record GateResult(
            boolean passed,
            String fromState,
            String toState,
            List<String> failedChecks,
            ModelStateSummary summary
    ) {
    }
}

