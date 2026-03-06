package com.adaptwaf.controlplane.repository.jdbc;

import com.adaptwaf.controlplane.repository.ExemptionRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;

/**
 * 豁免规则 JDBC 仓储实现。
 */
public class JdbcExemptionRepository implements ExemptionRepository {

    private static final String SELECT_APPROVED_SQL = """
            SELECT
                exemption_id, enabled, match_scope, detector, signature, method, route_key,
                content_type, surface, field_name, json_path, action, reason, owner,
                source_event_ids, expires_at, created_at
            FROM waf_exemption_rule
            WHERE enabled = 1
              AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP(3))
            ORDER BY rule_id ASC
            """;

    private static final String INSERT_RULE_SQL = """
            INSERT INTO waf_exemption_rule (
                exemption_id, enabled, match_scope, detector, signature, method, route_key,
                content_type, surface, field_name, json_path, action, reason, owner, source_event_ids, expires_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, CAST(? AS JSON), ?
            )
            """;

    private final DataSource dataSource;
    private final ObjectMapper objectMapper;

    public JdbcExemptionRepository(DataSource dataSource, ObjectMapper objectMapper) {
        this.dataSource = dataSource;
        this.objectMapper = objectMapper;
    }

    @Override
    public List<Map<String, Object>> loadApprovedRules() {
        List<Map<String, Object>> rules = new ArrayList<>();
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(SELECT_APPROVED_SQL);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                Map<String, Object> rule = new HashMap<>();
                rule.put("id", rs.getString("exemption_id"));
                rule.put("enabled", rs.getBoolean("enabled"));
                rule.put("match_scope", rs.getString("match_scope"));
                rule.put("detector", rs.getString("detector"));
                rule.put("signature", rs.getString("signature"));
                rule.put("method", rs.getString("method"));
                rule.put("route_key", rs.getString("route_key"));
                rule.put("content_type", rs.getString("content_type"));
                rule.put("surface", rs.getString("surface"));
                rule.put("field_name", rs.getString("field_name"));
                rule.put("json_path", rs.getString("json_path"));
                rule.put("action", rs.getString("action"));
                rule.put("reason", rs.getString("reason"));
                rule.put("owner", rs.getString("owner"));
                rule.put("source_event_ids", parseSourceEventIds(rs.getString("source_event_ids")));

                if (rs.getTimestamp("expires_at") != null) {
                    rule.put("expires_at", rs.getTimestamp("expires_at").toInstant().atOffset(ZoneOffset.UTC).toString());
                } else {
                    rule.put("expires_at", null);
                }

                if (rs.getTimestamp("created_at") != null) {
                    rule.put("created_at", rs.getTimestamp("created_at").toInstant().atOffset(ZoneOffset.UTC).toString());
                }
                rules.add(rule);
            }
            return rules;
        } catch (Exception e) {
            throw new IllegalStateException("exemption_rules_load_failed", e);
        }
    }

    private Object parseSourceEventIds(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        try {
            return objectMapper.readValue(raw, List.class);
        } catch (Exception ignored) {
            return List.of();
        }
    }

    @Override
    public void insertRule(Map<String, Object> rule) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(INSERT_RULE_SQL)) {
            int i = 1;
            ps.setString(i++, string(rule.get("id")));
            ps.setBoolean(i++, bool(rule.get("enabled"), true));
            ps.setString(i++, string(rule.get("match_scope")));
            ps.setString(i++, string(rule.get("detector")));
            ps.setString(i++, nullable(rule.get("signature")));
            ps.setString(i++, string(rule.get("method")));
            ps.setString(i++, string(rule.get("route_key")));
            ps.setString(i++, string(rule.get("content_type")));
            ps.setString(i++, string(rule.get("surface")));
            ps.setString(i++, string(rule.get("field_name")));
            ps.setString(i++, string(rule.get("json_path")));
            ps.setString(i++, string(rule.get("action")));
            ps.setString(i++, string(rule.get("reason")));
            ps.setString(i++, string(rule.get("owner")));
            ps.setString(i++, sourceIdsJson(rule.get("source_event_ids")));
            ps.setTimestamp(i++, parseTimestamp(nullable(rule.get("expires_at"))));
            ps.executeUpdate();
        } catch (Exception e) {
            throw new IllegalStateException("exemption_rule_insert_failed", e);
        }
    }

    private String string(Object value) {
        if (value == null) {
            return "";
        }
        return value.toString();
    }

    private String nullable(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString();
        return text.isBlank() ? null : text;
    }

    private boolean bool(Object value, boolean defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Boolean b) {
            return b;
        }
        return "true".equalsIgnoreCase(value.toString()) || "1".equals(value.toString());
    }

    private String sourceIdsJson(Object value) {
        try {
            if (value == null) {
                return "[]";
            }
            if (value instanceof String s) {
                return s.isBlank() ? "[]" : s;
            }
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "[]";
        }
    }

    private Timestamp parseTimestamp(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Timestamp.from(Instant.parse(raw));
        } catch (Exception ignored) {
            return null;
        }
    }
}
