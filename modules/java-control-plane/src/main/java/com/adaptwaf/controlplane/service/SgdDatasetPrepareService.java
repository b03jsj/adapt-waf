package com.adaptwaf.controlplane.service;

import com.adaptwaf.controlplane.config.ControlPlaneConfig;
import com.adaptwaf.controlplane.model.SgdDatasetPrepareResult;
import com.adaptwaf.controlplane.model.SgdDatasetSample;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.CRC32;
import javax.sql.DataSource;

/**
 * SGD 训练样本准备服务。
 * <p>
 * 目标：一条命令产出可直接用于离线训练的样本文件，避免人工拼接语料。
 */
public class SgdDatasetPrepareService {

    private static final String SQLI = "sqli";
    private static final String XSS = "xss";
    private static final String SQLI_MODEL_JSON_PATH = "$.model_sqli_input";
    private static final String XSS_MODEL_JSON_PATH = "$.model_xss_input";
    private static final String SQLI_SEED_CLASSPATH = "/sgd-seeds/sqli-payloads.txt";
    private static final String XSS_SEED_CLASSPATH = "/sgd-seeds/xss-payloads.txt";
    private static final DateTimeFormatter DIR_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss", Locale.ROOT).withZone(ZoneOffset.UTC);

    private static final String QUERY_STATE_SAMPLES_SQL = """
            SELECT
                e.event_id,
                e.event_time,
                e.route_key,
                e.field_name,
                e.detector,
                e.normalization_profile,
                JSON_UNQUOTE(JSON_EXTRACT(e.payload_json, ?)) AS model_input
            FROM waf_alert_event e
            JOIN waf_pattern_state ps ON ps.pattern_key_hash = e.pattern_key_hash
            WHERE ps.pattern_state = ?
              AND e.event_time >= ?
              AND e.event_time < ?
              AND e.normalization_profile = ?
              AND e.detector LIKE ?
              AND JSON_EXTRACT(e.payload_json, ?) IS NOT NULL
            ORDER BY e.event_time DESC
            LIMIT ?
            """;

    private static final String QUERY_HARD_NEGATIVE_SQL = """
            SELECT
                e.event_id,
                e.event_time,
                e.route_key,
                e.field_name,
                e.detector,
                e.normalization_profile,
                JSON_UNQUOTE(JSON_EXTRACT(e.payload_json, ?)) AS model_input
            FROM waf_alert_event e
            WHERE e.event_time >= ?
              AND e.event_time < ?
              AND e.normalization_profile = ?
              AND e.detector LIKE ?
              AND e.exemption_applied = 1
              AND e.policy_decision_basis IN ('parser_hit_exempted_exact', 'parser_hit_exempted_detector_field')
              AND JSON_EXTRACT(e.payload_json, ?) IS NOT NULL
            ORDER BY e.event_time DESC
            LIMIT ?
            """;

    private final DataSource dataSource;
    private final ObjectMapper objectMapper;
    private final ControlPlaneConfig config;

    public SgdDatasetPrepareService(
            DataSource dataSource,
            ObjectMapper objectMapper,
            ControlPlaneConfig config
    ) {
        this.dataSource = dataSource;
        this.objectMapper = objectMapper;
        this.config = config;
    }

    /**
     * 生成 SGD 训练样本。
     *
     * @param manualOutputDir 手工指定输出目录；为空则使用默认目录+UTC 时间戳子目录
     * @return 生成结果摘要
     * @throws Exception 读写或查询异常
     */
    public SgdDatasetPrepareResult prepare(Path manualOutputDir) throws Exception {
        Instant to = Instant.now();
        Instant from = to.minus(config.sgdDatasetWindow());

        Path outputDir = resolveOutputDir(manualOutputDir, to);
        Files.createDirectories(outputDir);

        List<SgdDatasetSample> sqliSamples = buildAttackTypeSamples(
                SQLI,
                SQLI_MODEL_JSON_PATH,
                "%sqli%",
                from,
                to
        );
        List<SgdDatasetSample> xssSamples = buildAttackTypeSamples(
                XSS,
                XSS_MODEL_JSON_PATH,
                "%xss%",
                from,
                to
        );

        writeAttackTypeFiles(outputDir, SQLI, sqliSamples);
        writeAttackTypeFiles(outputDir, XSS, xssSamples);

        List<SgdDatasetSample> all = new ArrayList<>(sqliSamples.size() + xssSamples.size());
        all.addAll(sqliSamples);
        all.addAll(xssSamples);

        Map<String, Long> sourceCounts = aggregateSourceCounts(all);
        Map<String, Long> attackTypeCounts = aggregateAttackTypeCounts(all);

        writeSummary(
                outputDir,
                from,
                to,
                sourceCounts,
                attackTypeCounts,
                all.size()
        );

        return new SgdDatasetPrepareResult(outputDir, all.size(), sourceCounts, attackTypeCounts);
    }

    private Path resolveOutputDir(Path manualOutputDir, Instant now) {
        if (manualOutputDir != null) {
            return manualOutputDir;
        }
        String runDir = DIR_TIME_FORMATTER.format(now);
        return config.sgdOutputRootDir().resolve(runDir);
    }

    private List<SgdDatasetSample> buildAttackTypeSamples(
            String attackType,
            String modelInputJsonPath,
            String detectorLike,
            Instant from,
            Instant to
    ) throws Exception {
        LinkedHashMap<String, SgdDatasetSample> dedup = new LinkedHashMap<>();

        if (config.sgdIncludeBuiltInSeeds()) {
            addBuiltInSeedPayloads(dedup, attackType);
        }

        addExternalPayloads(dedup, attackType);

        List<SgdDatasetSample> confirmedAttack = queryStateSamples(
                "attack_confirmed",
                attackType,
                modelInputJsonPath,
                detectorLike,
                from,
                to,
                config.sgdPositiveLimit()
        );
        mergeSamples(dedup, confirmedAttack);

        List<SgdDatasetSample> hardNegative = queryHardNegativeSamples(
                attackType,
                modelInputJsonPath,
                detectorLike,
                from,
                to,
                config.sgdHardNegativeLimit()
        );
        mergeSamples(dedup, hardNegative);

        List<SgdDatasetSample> benign = queryStateSamples(
                "benign_confirmed",
                attackType,
                modelInputJsonPath,
                detectorLike,
                from,
                to,
                config.sgdNegativeLimit()
        );
        mergeSamples(dedup, benign);

        List<SgdDatasetSample> result = new ArrayList<>(dedup.values());
        result.sort(Comparator.comparingInt(SgdDatasetSample::label).reversed().thenComparing(SgdDatasetSample::text));
        return result;
    }

    private void addBuiltInSeedPayloads(Map<String, SgdDatasetSample> dedup, String attackType) throws Exception {
        String resource = SQLI.equals(attackType) ? SQLI_SEED_CLASSPATH : XSS_SEED_CLASSPATH;
        try (InputStream inputStream = SgdDatasetPrepareService.class.getResourceAsStream(resource)) {
            if (inputStream != null) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
                    consumeSeedLines(reader, dedup, attackType, "seed_payload");
                    return;
                }
            }
        }

        // 兼容未打包 classpath 资源的本地开发场景。
        String localName = SQLI.equals(attackType) ? "sqli-payloads.txt" : "xss-payloads.txt";
        Path localSeedFile = Path.of("src/main/resources/sgd-seeds").resolve(localName);
        if (!Files.exists(localSeedFile)) {
            return;
        }
        try (BufferedReader reader = Files.newBufferedReader(localSeedFile, StandardCharsets.UTF_8)) {
            consumeSeedLines(reader, dedup, attackType, "seed_payload");
        }
    }

    private void consumeSeedLines(
            BufferedReader reader,
            Map<String, SgdDatasetSample> dedup,
            String attackType,
            String source
    ) throws Exception {
        String line;
        while ((line = reader.readLine()) != null) {
            String normalized = normalizeModelInput(line);
            if (normalized.isBlank()) {
                continue;
            }
            SgdDatasetSample sample = new SgdDatasetSample(
                    attackType,
                    1,
                    normalized,
                    source,
                    null,
                    null,
                    "-",
                    "-",
                    "-",
                    config.sgdNormalizationProfile()
            );
            mergeSample(dedup, sample);
        }
    }

    private void addExternalPayloads(Map<String, SgdDatasetSample> dedup, String attackType) throws Exception {
        Path file = SQLI.equals(attackType) ? config.sgdExtraSqliPayloadPath() : config.sgdExtraXssPayloadPath();
        if (file == null || !Files.exists(file)) {
            return;
        }

        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                String normalized = normalizeModelInput(line);
                if (normalized.isBlank()) {
                    continue;
                }
                SgdDatasetSample sample = new SgdDatasetSample(
                        attackType,
                        1,
                        normalized,
                        "tool_payload",
                        null,
                        null,
                        "-",
                        "-",
                        "-",
                        config.sgdNormalizationProfile()
                );
                mergeSample(dedup, sample);
            }
        }
    }

    private List<SgdDatasetSample> queryStateSamples(
            String state,
            String attackType,
            String modelInputJsonPath,
            String detectorLike,
            Instant from,
            Instant to,
            long limit
    ) throws Exception {
        int label = "attack_confirmed".equals(state) ? 1 : 0;
        String source = "attack_confirmed".equals(state) ? "attack_confirmed" : "benign_confirmed";
        List<SgdDatasetSample> result = new ArrayList<>();

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(QUERY_STATE_SAMPLES_SQL)) {
            int i = 1;
            ps.setString(i++, modelInputJsonPath);
            ps.setString(i++, state);
            ps.setTimestamp(i++, Timestamp.from(from));
            ps.setTimestamp(i++, Timestamp.from(to));
            ps.setString(i++, config.sgdNormalizationProfile());
            ps.setString(i++, detectorLike);
            ps.setString(i++, modelInputJsonPath);
            ps.setInt(i, safeLimit(limit));

            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String text = normalizeModelInput(rs.getString("model_input"));
                    if (text.isBlank()) {
                        continue;
                    }
                    result.add(new SgdDatasetSample(
                            attackType,
                            label,
                            text,
                            source,
                            rs.getString("event_id"),
                            toInstant(rs.getTimestamp("event_time")),
                            safeText(rs.getString("route_key")),
                            safeText(rs.getString("field_name")),
                            safeText(rs.getString("detector")),
                            safeText(rs.getString("normalization_profile"))
                    ));
                }
            }
        }

        return result;
    }

    private List<SgdDatasetSample> queryHardNegativeSamples(
            String attackType,
            String modelInputJsonPath,
            String detectorLike,
            Instant from,
            Instant to,
            long limit
    ) throws Exception {
        List<SgdDatasetSample> result = new ArrayList<>();
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(QUERY_HARD_NEGATIVE_SQL)) {
            int i = 1;
            ps.setString(i++, modelInputJsonPath);
            ps.setTimestamp(i++, Timestamp.from(from));
            ps.setTimestamp(i++, Timestamp.from(to));
            ps.setString(i++, config.sgdNormalizationProfile());
            ps.setString(i++, detectorLike);
            ps.setString(i++, modelInputJsonPath);
            ps.setInt(i, safeLimit(limit));

            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String text = normalizeModelInput(rs.getString("model_input"));
                    if (text.isBlank()) {
                        continue;
                    }
                    result.add(new SgdDatasetSample(
                            attackType,
                            0,
                            text,
                            "hard_negative",
                            rs.getString("event_id"),
                            toInstant(rs.getTimestamp("event_time")),
                            safeText(rs.getString("route_key")),
                            safeText(rs.getString("field_name")),
                            safeText(rs.getString("detector")),
                            safeText(rs.getString("normalization_profile"))
                    ));
                }
            }
        }
        return result;
    }

    private static int safeLimit(long limit) {
        long bounded = Math.max(1, Math.min(limit, Integer.MAX_VALUE));
        return (int) bounded;
    }

    private static Instant toInstant(Timestamp ts) {
        if (ts == null) {
            return null;
        }
        return ts.toInstant();
    }

    private static String safeText(String value) {
        if (value == null || value.isBlank()) {
            return "-";
        }
        return value;
    }

    private void mergeSamples(Map<String, SgdDatasetSample> dedup, List<SgdDatasetSample> samples) {
        for (SgdDatasetSample sample : samples) {
            mergeSample(dedup, sample);
        }
    }

    private void mergeSample(Map<String, SgdDatasetSample> dedup, SgdDatasetSample sample) {
        String key = sample.attackType() + "|" + sample.text();
        SgdDatasetSample existing = dedup.get(key);
        if (existing == null) {
            dedup.put(key, sample);
            return;
        }

        if (existing.label() == sample.label()) {
            return;
        }

        // 标签冲突时优先保留正样本，避免错过真实攻击模式。
        if (sample.label() > existing.label()) {
            dedup.put(key, sample);
        }
    }

    private void writeAttackTypeFiles(Path outputDir, String attackType, List<SgdDatasetSample> samples) throws Exception {
        Path allPath = outputDir.resolve(attackType + ".all.ndjson");
        Path trainPath = outputDir.resolve(attackType + ".train.ndjson");
        Path valPath = outputDir.resolve(attackType + ".val.ndjson");

        try (BufferedWriter allWriter = Files.newBufferedWriter(
                     allPath,
                     StandardCharsets.UTF_8,
                     StandardOpenOption.CREATE,
                     StandardOpenOption.TRUNCATE_EXISTING);
             BufferedWriter trainWriter = Files.newBufferedWriter(
                     trainPath,
                     StandardCharsets.UTF_8,
                     StandardOpenOption.CREATE,
                     StandardOpenOption.TRUNCATE_EXISTING);
             BufferedWriter valWriter = Files.newBufferedWriter(
                     valPath,
                     StandardCharsets.UTF_8,
                     StandardOpenOption.CREATE,
                     StandardOpenOption.TRUNCATE_EXISTING)) {
            for (SgdDatasetSample sample : samples) {
                String json = objectMapper.writeValueAsString(toJson(sample));
                allWriter.write(json);
                allWriter.newLine();

                if (isValidationSample(sample)) {
                    valWriter.write(json);
                    valWriter.newLine();
                } else {
                    trainWriter.write(json);
                    trainWriter.newLine();
                }
            }
        }
    }

    private Map<String, Object> toJson(SgdDatasetSample sample) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("attack_type", sample.attackType());
        payload.put("label", sample.label());
        payload.put("text", sample.text());
        payload.put("source", sample.source());
        payload.put("event_id", sample.eventId());
        payload.put("event_time", sample.eventTime() == null ? null : sample.eventTime().toString());
        payload.put("route_key", sample.routeKey());
        payload.put("field_name", sample.fieldName());
        payload.put("detector", sample.detector());
        payload.put("normalization_profile", sample.normalizationProfile());
        return payload;
    }

    private boolean isValidationSample(SgdDatasetSample sample) {
        CRC32 crc32 = new CRC32();
        byte[] bytes = (sample.attackType() + "|" + sample.text()).getBytes(StandardCharsets.UTF_8);
        crc32.update(bytes);
        return (crc32.getValue() % 10) == 0;
    }

    private Map<String, Long> aggregateSourceCounts(List<SgdDatasetSample> samples) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (SgdDatasetSample sample : samples) {
            counts.merge(sample.source(), 1L, Long::sum);
        }
        return counts;
    }

    private Map<String, Long> aggregateAttackTypeCounts(List<SgdDatasetSample> samples) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (SgdDatasetSample sample : samples) {
            String key = sample.attackType() + "_label_" + sample.label();
            counts.merge(key, 1L, Long::sum);
        }
        return counts;
    }

    private void writeSummary(
            Path outputDir,
            Instant from,
            Instant to,
            Map<String, Long> sourceCounts,
            Map<String, Long> attackTypeCounts,
            long totalSamples
    ) throws Exception {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("generated_at", Instant.now().toString());
        summary.put("window_from", from.toString());
        summary.put("window_to", to.toString());
        summary.put("normalization_profile", config.sgdNormalizationProfile());
        summary.put("total_samples", totalSamples);
        summary.put("source_counts", sourceCounts);
        summary.put("attack_type_counts", attackTypeCounts);
        summary.put("output_files", List.of(
                "sqli.all.ndjson",
                "sqli.train.ndjson",
                "sqli.val.ndjson",
                "xss.all.ndjson",
                "xss.train.ndjson",
                "xss.val.ndjson"
        ));

        Path summaryPath = outputDir.resolve("summary.json");
        try (BufferedWriter writer = Files.newBufferedWriter(
                summaryPath,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            writer.write(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(summary));
            writer.newLine();
        }
    }

    private String normalizeModelInput(String raw) {
        if (raw == null) {
            return "";
        }

        String value = raw.trim();
        if (value.isEmpty() || value.startsWith("#")) {
            return "";
        }

        StringBuilder builder = new StringBuilder(value.length());
        boolean prevWhitespace = false;
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch <= 0x7F) {
                ch = Character.toLowerCase(ch);
            }
            if (Character.isWhitespace(ch)) {
                if (!prevWhitespace) {
                    builder.append(' ');
                    prevWhitespace = true;
                }
                continue;
            }
            builder.append(ch);
            prevWhitespace = false;
            if (builder.length() >= 2048) {
                break;
            }
        }
        return builder.toString().trim();
    }
}
