package com.adaptwaf.controlplane.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * 控制面配置对象（配置文件驱动）。
 */
public record ControlPlaneConfig(
        boolean runtimeEnableApiServer,
        boolean runtimeEnableIngestLoop,
        boolean runtimeEnableAutoSuggestLoop,
        String mysqlUrl,
        String mysqlUser,
        String mysqlPassword,
        String sourceNode,
        Path alertLogPath,
        int ingestBatchSize,
        Duration ingestLoopInterval,
        Duration autoSuggestWindow,
        Duration autoSuggestLoopInterval,
        long autoSuggestMinHits,
        double autoSuggestMin2xxRatio,
        int autoSuggestMinUniqueIp,
        double autoSuggestMaxSingleIpRatio,
        double autoSuggestMinIpEntropyBits,
        int autoSuggestMinActiveDays,
        double autoSuggestMaxPeakDayRatio,
        Duration sgdDatasetWindow,
        long sgdPositiveLimit,
        long sgdNegativeLimit,
        long sgdHardNegativeLimit,
        String sgdNormalizationProfile,
        boolean sgdIncludeBuiltInSeeds,
        Path sgdOutputRootDir,
        Path sgdExtraSqliPayloadPath,
        Path sgdExtraXssPayloadPath,
        long sgdGateMinPositiveSamples,
        long sgdGateMinNegativeSamples,
        long sgdGateMinHardNegativeSamples,
        double sgdGateMinPrecisionAtAssistThreshold,
        double sgdGateMaxCleanFalsePositiveRate,
        double sgdGateMaxHardNegativeFalsePositiveRate,
        long sgdGateShadowObserveMinHours,
        double sgdGateShadowMaxFalsePositiveRate,
        double sgdGateShadowMaxRegressionDelta,
        Path exemptionsAuthoringSource,
        String reviewApiHost,
        int reviewApiPort,
        String reviewApiToken,
        int reviewBatchWorkerThreads,
        List<String> publishNodes,
        String openrestySharedSecret,
        int publishMaxAttempts,
        long publishRetryIntervalMillis
) {

    /**
     * 从 JSON 配置文件加载配置。
     *
     * @param configPath 配置文件路径
     * @return 配置对象
     * @throws Exception 读取或解析失败
     */
    public static ControlPlaneConfig fromFile(Path configPath) throws Exception {
        if (configPath == null) {
            throw new IllegalArgumentException("config_path_required");
        }
        if (!Files.exists(configPath)) {
            throw new IllegalArgumentException("config_file_not_found:" + configPath.toAbsolutePath());
        }

        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(Files.readAllBytes(configPath));
        if (root == null || !root.isObject()) {
            throw new IllegalArgumentException("config_root_must_be_object");
        }

        JsonNode runtime = section(root, "runtime");
        JsonNode mysql = section(root, "mysql");
        JsonNode ingest = section(root, "ingest");
        JsonNode autoSuggest = section(root, "auto_suggest");
        JsonNode sgdDataset = section(root, "sgd_dataset");
        JsonNode sgdGate = section(root, "sgd_gate");
        JsonNode exemptions = section(root, "exemptions");
        JsonNode reviewApi = section(root, "review_api");
        JsonNode publish = section(root, "publish");

        boolean runtimeEnableApiServer = bool(runtime, "enable_api_server", true);
        boolean runtimeEnableIngestLoop = bool(runtime, "enable_ingest_loop", true);
        boolean runtimeEnableAutoSuggestLoop = bool(runtime, "enable_auto_suggest_loop", true);

        String mysqlUrl = text(mysql, "url", "jdbc:mysql://127.0.0.1:3306/waf?useUnicode=true&characterEncoding=utf8");
        String mysqlUser = text(mysql, "user", "waf");
        String mysqlPassword = text(mysql, "password", "waf");

        String sourceNode = text(ingest, "source_node", "local-node");
        Path alertLogPath = path(ingest, "alert_log_path", "/var/log/nginx/waf-alert.ndjson");
        int ingestBatchSize = intNumber(ingest, "batch_size", 2000);
        Duration ingestLoopInterval = Duration.ofSeconds(longNumber(ingest, "loop_interval_seconds", 5));

        Duration autoSuggestWindow = Duration.ofHours(longNumber(autoSuggest, "window_hours", 168));
        Duration autoSuggestLoopInterval = Duration.ofSeconds(longNumber(autoSuggest, "loop_interval_seconds", 300));
        long autoSuggestMinHits = longNumber(autoSuggest, "min_hits", 200);
        double autoSuggestMin2xxRatio = doubleNumber(autoSuggest, "min_2xx_ratio", 0.995);
        int autoSuggestMinUniqueIp = intNumber(autoSuggest, "min_unique_ip", 20);
        double autoSuggestMaxSingleIpRatio = doubleNumber(autoSuggest, "max_single_ip_ratio", 0.2);
        double autoSuggestMinIpEntropyBits = doubleNumber(autoSuggest, "min_ip_entropy", 2.5);
        int autoSuggestMinActiveDays = intNumber(autoSuggest, "min_active_days", 2);
        double autoSuggestMaxPeakDayRatio = doubleNumber(autoSuggest, "max_peak_day_ratio", 0.7);

        Duration sgdDatasetWindow = Duration.ofHours(longNumber(sgdDataset, "window_hours", 168));
        long sgdPositiveLimit = longNumber(sgdDataset, "positive_limit", 50000);
        long sgdNegativeLimit = longNumber(sgdDataset, "negative_limit", 100000);
        long sgdHardNegativeLimit = longNumber(sgdDataset, "hard_negative_limit", 30000);
        String sgdNormalizationProfile = text(sgdDataset, "normalization_profile", "norm-v1");
        boolean sgdIncludeBuiltInSeeds = bool(sgdDataset, "include_builtin_seeds", true);
        Path sgdOutputRootDir = path(sgdDataset, "output_dir", "./out/sgd-dataset");
        Path sgdExtraSqliPayloadPath = nullablePath(sgdDataset, "extra_sqli_payload_path");
        Path sgdExtraXssPayloadPath = nullablePath(sgdDataset, "extra_xss_payload_path");

        long sgdGateMinPositiveSamples = longNumber(sgdGate, "min_positive_samples", 1000);
        long sgdGateMinNegativeSamples = longNumber(sgdGate, "min_negative_samples", 5000);
        long sgdGateMinHardNegativeSamples = longNumber(sgdGate, "min_hard_negative_samples", 1000);
        double sgdGateMinPrecisionAtAssistThreshold =
                doubleNumber(sgdGate, "min_precision_at_assist_threshold", 0.95);
        double sgdGateMaxCleanFalsePositiveRate =
                doubleNumber(sgdGate, "max_clean_false_positive_rate", 0.001);
        double sgdGateMaxHardNegativeFalsePositiveRate =
                doubleNumber(sgdGate, "max_hard_negative_false_positive_rate", 0.01);
        long sgdGateShadowObserveMinHours = longNumber(sgdGate, "shadow_observe_min_hours", 72);
        double sgdGateShadowMaxFalsePositiveRate =
                doubleNumber(sgdGate, "shadow_max_false_positive_rate", 0.01);
        double sgdGateShadowMaxRegressionDelta =
                doubleNumber(sgdGate, "shadow_max_regression_delta", 0.02);

        Path exemptionsAuthoringSource = nullablePath(exemptions, "authoring_source");

        String reviewApiHost = text(reviewApi, "host", "0.0.0.0");
        int reviewApiPort = intNumber(reviewApi, "port", 28080);
        String reviewApiToken = text(reviewApi, "token", "");
        int reviewBatchWorkerThreads = intNumber(reviewApi, "batch_worker_threads", 2);

        List<String> publishNodes = list(publish, "nodes");
        String sharedSecret = text(publish, "shared_secret", "change_me");
        int publishMaxAttempts = intNumber(publish, "max_attempts", 3);
        long publishRetryIntervalMillis = longNumber(publish, "retry_interval_ms", 1000);

        return new ControlPlaneConfig(
                runtimeEnableApiServer,
                runtimeEnableIngestLoop,
                runtimeEnableAutoSuggestLoop,
                mysqlUrl,
                mysqlUser,
                mysqlPassword,
                sourceNode,
                alertLogPath,
                ingestBatchSize,
                ingestLoopInterval,
                autoSuggestWindow,
                autoSuggestLoopInterval,
                autoSuggestMinHits,
                autoSuggestMin2xxRatio,
                autoSuggestMinUniqueIp,
                autoSuggestMaxSingleIpRatio,
                autoSuggestMinIpEntropyBits,
                autoSuggestMinActiveDays,
                autoSuggestMaxPeakDayRatio,
                sgdDatasetWindow,
                sgdPositiveLimit,
                sgdNegativeLimit,
                sgdHardNegativeLimit,
                sgdNormalizationProfile,
                sgdIncludeBuiltInSeeds,
                sgdOutputRootDir,
                sgdExtraSqliPayloadPath,
                sgdExtraXssPayloadPath,
                sgdGateMinPositiveSamples,
                sgdGateMinNegativeSamples,
                sgdGateMinHardNegativeSamples,
                sgdGateMinPrecisionAtAssistThreshold,
                sgdGateMaxCleanFalsePositiveRate,
                sgdGateMaxHardNegativeFalsePositiveRate,
                sgdGateShadowObserveMinHours,
                sgdGateShadowMaxFalsePositiveRate,
                sgdGateShadowMaxRegressionDelta,
                exemptionsAuthoringSource,
                reviewApiHost,
                reviewApiPort,
                reviewApiToken,
                reviewBatchWorkerThreads,
                publishNodes,
                sharedSecret,
                publishMaxAttempts,
                publishRetryIntervalMillis
        );
    }

    private static JsonNode section(JsonNode root, String key) {
        JsonNode node = root.path(key);
        if (node.isMissingNode() || node.isNull() || !node.isObject()) {
            return null;
        }
        return node;
    }

    private static String text(JsonNode section, String key, String defaultValue) {
        if (section == null) {
            return defaultValue;
        }
        JsonNode node = section.get(key);
        if (node == null || node.isNull()) {
            return defaultValue;
        }
        String value = node.asText();
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        return value;
    }

    private static boolean bool(JsonNode section, String key, boolean defaultValue) {
        if (section == null) {
            return defaultValue;
        }
        JsonNode node = section.get(key);
        if (node == null || node.isNull()) {
            return defaultValue;
        }
        if (node.isBoolean()) {
            return node.asBoolean();
        }
        String value = node.asText();
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        String lowered = value.trim().toLowerCase();
        if ("1".equals(lowered) || "true".equals(lowered) || "yes".equals(lowered) || "on".equals(lowered)) {
            return true;
        }
        if ("0".equals(lowered) || "false".equals(lowered) || "no".equals(lowered) || "off".equals(lowered)) {
            return false;
        }
        return defaultValue;
    }

    private static int intNumber(JsonNode section, String key, int defaultValue) {
        if (section == null) {
            return defaultValue;
        }
        JsonNode node = section.get(key);
        if (node == null || node.isNull()) {
            return defaultValue;
        }
        if (node.isNumber()) {
            return node.asInt(defaultValue);
        }
        try {
            return Integer.parseInt(node.asText().trim());
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private static long longNumber(JsonNode section, String key, long defaultValue) {
        if (section == null) {
            return defaultValue;
        }
        JsonNode node = section.get(key);
        if (node == null || node.isNull()) {
            return defaultValue;
        }
        if (node.isNumber()) {
            return node.asLong(defaultValue);
        }
        try {
            return Long.parseLong(node.asText().trim());
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private static double doubleNumber(JsonNode section, String key, double defaultValue) {
        if (section == null) {
            return defaultValue;
        }
        JsonNode node = section.get(key);
        if (node == null || node.isNull()) {
            return defaultValue;
        }
        if (node.isNumber()) {
            return node.asDouble(defaultValue);
        }
        try {
            return Double.parseDouble(node.asText().trim());
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private static Path path(JsonNode section, String key, String defaultValue) {
        String text = text(section, key, defaultValue);
        return Path.of(text);
    }

    private static Path nullablePath(JsonNode section, String key) {
        if (section == null) {
            return null;
        }
        JsonNode node = section.get(key);
        if (node == null || node.isNull()) {
            return null;
        }
        String value = node.asText();
        if (value == null || value.isBlank()) {
            return null;
        }
        return Path.of(value);
    }

    private static List<String> list(JsonNode section, String key) {
        if (section == null) {
            return List.of();
        }
        JsonNode node = section.get(key);
        if (node == null || node.isNull()) {
            return List.of();
        }

        List<String> values = new ArrayList<>();
        if (node.isArray()) {
            for (JsonNode item : node) {
                if (item == null || item.isNull()) {
                    continue;
                }
                String value = item.asText();
                if (value != null && !value.isBlank()) {
                    values.add(value.trim());
                }
            }
            return List.copyOf(values);
        }

        String text = node.asText();
        if (text == null || text.isBlank()) {
            return List.of();
        }
        for (String token : text.split(",")) {
            if (token != null && !token.isBlank()) {
                values.add(token.trim());
            }
        }
        return List.copyOf(values);
    }
}
