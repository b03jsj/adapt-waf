package com.adaptwaf.controlplane.service;

import com.adaptwaf.controlplane.repository.ExemptionRepository;
import com.adaptwaf.controlplane.repository.PatternStateRepository;
import com.adaptwaf.controlplane.util.HashUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Set;

/**
 * 豁免规则编译服务。
 * 说明：支持“仓储读取规则”与“authoring 文件(YAML/JSON)”两种编译入口。
 */
public class ExemptionCompilerService {

    private static final String SCOPE_SIGNATURE_EXACT = "signature_exact";
    private static final String SCOPE_DETECTOR_FIELD = "detector_field";
    private static final Set<String> DETECTOR_FIELD_ALLOWED = Set.of("libinjection_sqli", "libinjection_xss");

    private final ExemptionRepository exemptionRepository;
    private final PatternStateRepository patternStateRepository;
    private final ObjectMapper objectMapper;

    public ExemptionCompilerService(
            ExemptionRepository exemptionRepository,
            PatternStateRepository patternStateRepository,
            ObjectMapper objectMapper
    ) {
        this.exemptionRepository = exemptionRepository;
        this.patternStateRepository = patternStateRepository;
        this.objectMapper = objectMapper;
    }

    /**
     * 编译当前审批后的规则，输出运行时快照内容。
     *
     * @param generation 目标代次
     * @param publishId 发布任务标识
     * @return 编译结果（JSON 字节与 SHA256）
     * @throws Exception 编译失败异常
     */
    public CompiledResult compile(long generation, String publishId) throws Exception {
        return compileFromRules(generation, publishId, exemptionRepository.loadApprovedRules());
    }

    /**
     * 从 authoring 文件（YAML/JSON）编译豁免快照。
     *
     * @param generation 目标代次
     * @param publishId 发布任务标识
     * @param sourcePath authoring 文件路径
     * @return 编译结果
     * @throws Exception 编译失败异常
     */
    public CompiledResult compileFromAuthoringFile(long generation, String publishId, Path sourcePath) throws Exception {
        if (sourcePath == null || !Files.exists(sourcePath)) {
            throw new IllegalArgumentException("authoring_source_not_found:" + sourcePath);
        }
        String text = Files.readString(sourcePath, StandardCharsets.UTF_8);
        List<Map<String, Object>> rules = parseAuthoringRules(text);
        return compileFromRules(generation, publishId, rules);
    }

    /**
     * 基于规则列表编译快照。
     *
     * @param generation 目标代次
     * @param publishId 发布任务标识
     * @param rawRules 原始规则列表
     * @return 编译结果
     * @throws Exception 编译失败异常
     */
    public CompiledResult compileFromRules(long generation, String publishId, List<Map<String, Object>> rawRules) throws Exception {
        List<Map<String, Object>> rules = normalizeAndValidate(rawRules);
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("generation", generation);
        root.put("publish_id", publishId);
        root.put("schema_version", "exemptions-compiled-v1");
        root.put("rules", rules);
        root.put("pattern_state_index", buildPatternStateIndex());

        byte[] content = objectMapper.writeValueAsBytes(root);
        String sha256 = HashUtils.sha256Hex(content);
        return new CompiledResult(content, sha256);
    }

    /**
     * 构建运行时模式状态索引。
     */
    private Map<String, Object> buildPatternStateIndex() {
        Map<String, Object> result = new LinkedHashMap<>();
        List<String> benign = new ArrayList<>();
        List<String> attack = new ArrayList<>();
        result.put("benign_confirmed", benign);
        result.put("attack_confirmed", attack);

        if (patternStateRepository == null) {
            return result;
        }

        Map<String, String> runtimeIndex = patternStateRepository.loadRuntimePatternStateIndex();
        for (Map.Entry<String, String> entry : runtimeIndex.entrySet()) {
            String keyHash = entry.getKey();
            String state = entry.getValue();
            if ("benign_confirmed".equals(state)) {
                benign.add(keyHash);
            } else if ("attack_confirmed".equals(state)) {
                attack.add(keyHash);
            }
        }
        return result;
    }

    /**
     * 归一化并校验豁免规则，避免把非法规则发布到运行时。
     *
     * @param rules 原始规则
     * @return 可发布规则
     */
    private List<Map<String, Object>> normalizeAndValidate(List<Map<String, Object>> rules) {
        List<Map<String, Object>> normalizedRules = new ArrayList<>();
        Set<String> exactKeys = new HashSet<>();
        Set<String> detectorFieldKeys = new HashSet<>();

        for (Map<String, Object> rawRule : rules) {
            Map<String, Object> rule = normalizeRule(rawRule);
            String scope = stringValue(rule.get("match_scope"), SCOPE_SIGNATURE_EXACT);
            String detector = stringValue(rule.get("detector"), "-");

            if (!SCOPE_SIGNATURE_EXACT.equals(scope) && !SCOPE_DETECTOR_FIELD.equals(scope)) {
                throw new IllegalStateException("invalid_match_scope:" + scope);
            }
            if (SCOPE_DETECTOR_FIELD.equals(scope) && !DETECTOR_FIELD_ALLOWED.contains(detector)) {
                throw new IllegalStateException("detector_scope_not_allowed:" + detector);
            }

            String dedupKey = SCOPE_SIGNATURE_EXACT.equals(scope) ? buildExactKey(rule) : buildDetectorFieldKey(rule);
            Set<String> targetSet = SCOPE_SIGNATURE_EXACT.equals(scope) ? exactKeys : detectorFieldKeys;
            if (!targetSet.add(dedupKey)) {
                throw new IllegalStateException("duplicate_rule_key:" + dedupKey);
            }

            normalizedRules.add(rule);
        }

        return normalizedRules;
    }

    /**
     * 解析 authoring 规则文本。
     * 支持：
     * - JSON：对象格式 {"exemptions":[...]} 或数组 [...]
     * - YAML：仅支持首版受控子集（exemptions 顶层 + map/list 标量）
     */
    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> parseAuthoringRules(String text) throws Exception {
        String trimmed = (text == null ? "" : text.trim());
        if (trimmed.isEmpty()) {
            return List.of();
        }

        // 优先按 JSON 解析，失败再走 YAML 子集解析。
        try {
            JsonNode node = objectMapper.readTree(trimmed);
            if (node.isArray()) {
                return objectMapper.convertValue(node, List.class);
            }
            if (node.isObject()) {
                JsonNode exemptions = node.get("exemptions");
                if (exemptions == null || exemptions.isNull()) {
                    return List.of();
                }
                return objectMapper.convertValue(exemptions, List.class);
            }
            throw new IllegalStateException("authoring_json_invalid_root");
        } catch (Exception ignored) {
            // 降级到 YAML 子集解析。
        }

        return parseYamlSubset(trimmed);
    }

    /**
     * 解析 YAML 受控子集。
     * 约束：
     * - 顶层仅支持 `exemptions:`
     * - 条目以 `-` 开头
     * - 支持 `key: value`、内联列表 `[a,b]`、块列表
     */
    private List<Map<String, Object>> parseYamlSubset(String text) {
        List<Map<String, Object>> rules = new ArrayList<>();
        Map<String, Object> current = null;
        String currentListKey = null;
        List<Object> currentList = null;
        int currentListIndent = -1;

        String[] lines = text.split("\\r?\\n");
        for (String rawLine : lines) {
            String line = stripComment(rawLine);
            if (line.isBlank()) {
                continue;
            }
            int indent = countLeadingSpaces(line);
            String trimmed = line.trim();

            if ("exemptions:".equals(trimmed)) {
                continue;
            }

            if (currentListKey != null) {
                if (indent > currentListIndent && trimmed.startsWith("- ")) {
                    currentList.add(parseScalar(trimmed.substring(2).trim()));
                    continue;
                }
                currentListKey = null;
                currentList = null;
                currentListIndent = -1;
            }

            if (trimmed.startsWith("- ")) {
                if (current != null) {
                    rules.add(current);
                }
                current = new LinkedHashMap<>();
                String inline = trimmed.substring(2).trim();
                if (!inline.isEmpty()) {
                    putYamlKeyValue(current, inline);
                }
                continue;
            }

            if (current == null) {
                throw new IllegalStateException("yaml_rule_parse_error:entry_missing");
            }

            int colon = trimmed.indexOf(':');
            if (colon <= 0) {
                throw new IllegalStateException("yaml_rule_parse_error:invalid_line:" + trimmed);
            }

            String key = trimmed.substring(0, colon).trim();
            String value = trimmed.substring(colon + 1).trim();
            if (value.isEmpty()) {
                currentListKey = key;
                currentList = new ArrayList<>();
                current.put(key, currentList);
                currentListIndent = indent;
                continue;
            }
            current.put(key, parseScalar(value));
        }

        if (current != null) {
            rules.add(current);
        }
        return rules;
    }

    private void putYamlKeyValue(Map<String, Object> target, String inline) {
        int colon = inline.indexOf(':');
        if (colon <= 0) {
            throw new IllegalStateException("yaml_rule_parse_error:invalid_inline:" + inline);
        }
        String key = inline.substring(0, colon).trim();
        String value = inline.substring(colon + 1).trim();
        target.put(key, parseScalar(value));
    }

    private int countLeadingSpaces(String line) {
        int count = 0;
        while (count < line.length() && line.charAt(count) == ' ') {
            count++;
        }
        return count;
    }

    private String stripComment(String line) {
        if (line == null) {
            return "";
        }
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        for (int i = 0; i < line.length(); i++) {
            char ch = line.charAt(i);
            if (ch == '\'' && !inDoubleQuote) {
                inSingleQuote = !inSingleQuote;
            } else if (ch == '"' && !inSingleQuote) {
                inDoubleQuote = !inDoubleQuote;
            } else if (ch == '#' && !inSingleQuote && !inDoubleQuote) {
                return line.substring(0, i);
            }
        }
        return line;
    }

    private Object parseScalar(String value) {
        String raw = value == null ? "" : value.trim();
        if (raw.isEmpty()) {
            return "";
        }

        if (raw.startsWith("[") && raw.endsWith("]")) {
            String inner = raw.substring(1, raw.length() - 1).trim();
            if (inner.isEmpty()) {
                return List.of();
            }
            String[] tokens = inner.split(",");
            List<Object> list = new ArrayList<>(tokens.length);
            for (String token : tokens) {
                list.add(parseScalar(token));
            }
            return list;
        }

        if ((raw.startsWith("\"") && raw.endsWith("\"")) || (raw.startsWith("'") && raw.endsWith("'"))) {
            return raw.substring(1, raw.length() - 1);
        }

        String lowered = raw.toLowerCase(Locale.ROOT);
        if ("true".equals(lowered)) {
            return true;
        }
        if ("false".equals(lowered)) {
            return false;
        }
        if ("null".equals(lowered) || "~".equals(raw)) {
            return null;
        }

        if (raw.matches("^-?\\d+$")) {
            try {
                return Long.parseLong(raw);
            } catch (Exception ignored) {
                // ignore
            }
        }
        if (raw.matches("^-?\\d+\\.\\d+$")) {
            try {
                return Double.parseDouble(raw);
            } catch (Exception ignored) {
                // ignore
            }
        }
        return raw;
    }

    /**
     * 统一规则字段格式，保证 Java 与 OpenResty 构造键一致。
     *
     * @param rawRule 原始规则
     * @return 归一化规则
     */
    private Map<String, Object> normalizeRule(Map<String, Object> rawRule) {
        Map<String, Object> rule = new LinkedHashMap<>();
        rule.put("id", stringValue(rawRule.get("id"), "-"));
        rule.put("enabled", rawRule.getOrDefault("enabled", Boolean.TRUE));
        rule.put("match_scope", stringValue(rawRule.get("match_scope"), SCOPE_SIGNATURE_EXACT));
        rule.put("detector", stringValue(rawRule.get("detector"), "-"));
        rule.put("signature", stringValue(rawRule.get("signature"), "-"));
        rule.put("method", stringValue(rawRule.get("method"), "-").toUpperCase(Locale.ROOT));
        rule.put("route_key", stringValue(rawRule.get("route_key"), "-"));
        rule.put("content_type", stringValue(rawRule.get("content_type"), "-").toLowerCase(Locale.ROOT));
        rule.put("surface", stringValue(rawRule.get("surface"), "-"));
        rule.put("field_name", stringValue(rawRule.get("field_name"), "-"));
        rule.put("json_path", stringValue(rawRule.get("json_path"), "-"));
        rule.put("action", stringValue(rawRule.get("action"), "allow_log"));
        rule.put("reason", stringValue(rawRule.get("reason"), "-"));
        rule.put("owner", stringValue(rawRule.get("owner"), "-"));
        rule.put("source_event_ids", rawRule.getOrDefault("source_event_ids", List.of()));
        rule.put("created_at", rawRule.get("created_at"));
        rule.put("expires_at", rawRule.get("expires_at"));
        return rule;
    }

    private String buildExactKey(Map<String, Object> rule) {
        return String.join("|",
                stringValue(rule.get("method"), "-"),
                stringValue(rule.get("route_key"), "-"),
                stringValue(rule.get("content_type"), "-"),
                stringValue(rule.get("surface"), "-"),
                fieldSelector(rule),
                stringValue(rule.get("detector"), "-"),
                stringValue(rule.get("signature"), "-")
        );
    }

    private String buildDetectorFieldKey(Map<String, Object> rule) {
        return String.join("|",
                stringValue(rule.get("method"), "-"),
                stringValue(rule.get("route_key"), "-"),
                stringValue(rule.get("content_type"), "-"),
                stringValue(rule.get("surface"), "-"),
                fieldSelector(rule),
                stringValue(rule.get("detector"), "-")
        );
    }

    private String fieldSelector(Map<String, Object> rule) {
        String surface = stringValue(rule.get("surface"), "-");
        if ("json".equals(surface)) {
            return stringValue(rule.get("json_path"), "-");
        }
        return stringValue(rule.get("field_name"), "-");
    }

    private String stringValue(Object value, String defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        String text = value.toString();
        if (text.isBlank()) {
            return defaultValue;
        }
        return text;
    }

    /**
     * 编译结果对象。
     *
     * @param content 编译内容
     * @param sha256 内容哈希
     */
    public record CompiledResult(byte[] content, String sha256) {
    }
}
