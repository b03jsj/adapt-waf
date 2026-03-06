package com.adaptwaf.controlplane.repository.jdbc;

import com.adaptwaf.controlplane.model.FirstSeenEvent;
import com.adaptwaf.controlplane.model.FirstSeenQuery;
import com.adaptwaf.controlplane.model.WafAlertEvent;
import com.adaptwaf.controlplane.repository.AlertEventRepository;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import javax.sql.DataSource;

/**
 * 告警事件 JDBC 仓储实现。
 */
public class JdbcAlertEventRepository implements AlertEventRepository {

    private static final String UPSERT_SQL = """
            INSERT INTO waf_alert_event (
                event_id, event_time, event_date, route_key, method, content_type, surface,
                field_name, json_path, detector, detector_signature, threat_classification,
                alert_level, final_action, status_code, client_ip, user_agent_hash,
                pattern_key, pattern_key_text, pattern_key_hash,
                first_seen_pattern, exemption_applied, exemption_id, exemption_match_scope,
                policy_decision_basis, normalization_profile, payload_json
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?
            )
            ON DUPLICATE KEY UPDATE
                event_id = event_id
            """;

    private static final String QUERY_FIRST_SEEN_BASE_SQL = """
            SELECT
                event_id, event_time, route_key, method, content_type, surface,
                field_name, json_path, detector, detector_signature, pattern_key,
                alert_level, final_action, policy_decision_basis
            FROM waf_alert_event e
            LEFT JOIN waf_pattern_state ps ON ps.pattern_key_hash = e.pattern_key_hash
            WHERE first_seen_pattern = 1
              AND (ps.pattern_state IS NULL OR ps.pattern_state = 'unknown')
            """;

    private static final String COUNT_FIRST_SEEN_BASE_SQL = """
            SELECT COUNT(1)
            FROM waf_alert_event e
            LEFT JOIN waf_pattern_state ps ON ps.pattern_key_hash = e.pattern_key_hash
            WHERE first_seen_pattern = 1
              AND (ps.pattern_state IS NULL OR ps.pattern_state = 'unknown')
            """;

    private final DataSource dataSource;

    public JdbcAlertEventRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public void saveBatch(List<WafAlertEvent> events) {
        if (events == null || events.isEmpty()) {
            return;
        }

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(UPSERT_SQL)) {
            connection.setAutoCommit(false);

            for (WafAlertEvent event : events) {
                int i = 1;
                ps.setString(i++, event.eventId());
                ps.setTimestamp(i++, Timestamp.from(event.eventTime()));
                ps.setObject(i++, LocalDate.ofInstant(event.eventTime(), ZoneOffset.UTC));
                ps.setString(i++, event.routeKey());
                ps.setString(i++, event.method());
                ps.setString(i++, event.contentType());
                ps.setString(i++, event.surface());
                ps.setString(i++, event.fieldName());
                ps.setString(i++, event.jsonPath());
                ps.setString(i++, event.detector());
                ps.setString(i++, event.detectorSignature());
                ps.setString(i++, toThreatClass(event.finalAction()));
                ps.setString(i++, event.alertLevel());
                ps.setString(i++, event.finalAction());
                ps.setInt(i++, event.statusCode());
                ps.setString(i++, event.clientIp());
                ps.setString(i++, event.userAgentHash());
                ps.setString(i++, event.patternKey());
                ps.setString(i++, event.patternKey());
                ps.setString(i++, event.patternKeyHash());
                ps.setBoolean(i++, event.firstSeenPattern());
                ps.setBoolean(i++, event.exemptionApplied());
                ps.setString(i++, event.exemptionId());
                ps.setString(i++, event.exemptionMatchScope());
                ps.setString(i++, event.policyDecisionBasis());
                ps.setString(i++, event.normalizationProfile());
                ps.setString(i++, event.payloadJson());
                ps.addBatch();
            }

            ps.executeBatch();
            connection.commit();
        } catch (Exception e) {
            throw new IllegalStateException("alert_event_batch_save_failed", e);
        }
    }

    private String toThreatClass(String finalAction) {
        if ("block".equals(finalAction)) {
            return "confirmed_attack";
        }
        if ("high_alert".equals(finalAction) || "log".equals(finalAction)) {
            return "suspected_attack";
        }
        return "none";
    }

    @Override
    public List<FirstSeenEvent> listFirstSeenQueue(int limit, int offset) {
        FirstSeenQuery query = new FirstSeenQuery(
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
        );
        return listFirstSeenQueue(query, limit, offset);
    }

    @Override
    public List<FirstSeenEvent> listFirstSeenQueue(FirstSeenQuery query, int limit, int offset) {
        int safeLimit = Math.max(1, Math.min(limit, 500));
        int safeOffset = Math.max(offset, 0);
        List<FirstSeenEvent> result = new ArrayList<>(safeLimit);

        StringBuilder sql = new StringBuilder(QUERY_FIRST_SEEN_BASE_SQL);
        List<Object> params = new ArrayList<>();

        if (blank(query.alertLevel())) {
            sql.append(" AND alert_level IN ('high', 'critical')");
        } else {
            sql.append(" AND alert_level = ?");
            params.add(query.alertLevel());
        }
        if (!blank(query.routeKey())) {
            sql.append(" AND route_key = ?");
            params.add(query.routeKey());
        }
        if (!blank(query.detector())) {
            sql.append(" AND detector = ?");
            params.add(query.detector());
        }
        if (!blank(query.method())) {
            sql.append(" AND method = ?");
            params.add(query.method());
        }
        if (!blank(query.contentType())) {
            sql.append(" AND content_type = ?");
            params.add(query.contentType());
        }
        if (!blank(query.surface())) {
            sql.append(" AND surface = ?");
            params.add(query.surface());
        }
        if (query.fromTime() != null) {
            sql.append(" AND event_time >= ?");
            params.add(Timestamp.from(query.fromTime()));
        }
        if (query.toTime() != null) {
            sql.append(" AND event_time < ?");
            params.add(Timestamp.from(query.toTime()));
        }
        sql.append(" ORDER BY event_time DESC LIMIT ? OFFSET ?");
        params.add(safeLimit);
        params.add(safeOffset);

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql.toString())) {
            bindParams(ps, params);

            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    result.add(new FirstSeenEvent(
                            rs.getString("event_id"),
                            rs.getTimestamp("event_time").toInstant().atZone(ZoneId.of("UTC")).toInstant(),
                            rs.getString("route_key"),
                            rs.getString("method"),
                            rs.getString("content_type"),
                            rs.getString("surface"),
                            rs.getString("field_name"),
                            rs.getString("json_path"),
                            rs.getString("detector"),
                            rs.getString("detector_signature"),
                            rs.getString("pattern_key"),
                            rs.getString("alert_level"),
                            rs.getString("final_action"),
                            rs.getString("policy_decision_basis")
                    ));
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException("first_seen_queue_query_failed", e);
        }

        return result;
    }

    @Override
    public long countFirstSeenQueue(FirstSeenQuery query) {
        FirstSeenQuery safeQuery = (query == null)
                ? new FirstSeenQuery(null, null, null, null, null, null, null, null)
                : query;

        StringBuilder sql = new StringBuilder(COUNT_FIRST_SEEN_BASE_SQL);
        List<Object> params = new ArrayList<>();

        if (blank(safeQuery.alertLevel())) {
            sql.append(" AND alert_level IN ('high', 'critical')");
        } else {
            sql.append(" AND alert_level = ?");
            params.add(safeQuery.alertLevel());
        }
        if (!blank(safeQuery.routeKey())) {
            sql.append(" AND route_key = ?");
            params.add(safeQuery.routeKey());
        }
        if (!blank(safeQuery.detector())) {
            sql.append(" AND detector = ?");
            params.add(safeQuery.detector());
        }
        if (!blank(safeQuery.method())) {
            sql.append(" AND method = ?");
            params.add(safeQuery.method());
        }
        if (!blank(safeQuery.contentType())) {
            sql.append(" AND content_type = ?");
            params.add(safeQuery.contentType());
        }
        if (!blank(safeQuery.surface())) {
            sql.append(" AND surface = ?");
            params.add(safeQuery.surface());
        }
        if (safeQuery.fromTime() != null) {
            sql.append(" AND event_time >= ?");
            params.add(Timestamp.from(safeQuery.fromTime()));
        }
        if (safeQuery.toTime() != null) {
            sql.append(" AND event_time < ?");
            params.add(Timestamp.from(safeQuery.toTime()));
        }

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql.toString())) {
            bindParams(ps, params);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getLong(1);
                }
                return 0L;
            }
        } catch (Exception e) {
            throw new IllegalStateException("first_seen_queue_count_failed", e);
        }
    }

    private void bindParams(PreparedStatement ps, List<Object> params) throws Exception {
        for (int i = 0; i < params.size(); i++) {
            Object value = params.get(i);
            int index = i + 1;
            if (value instanceof Timestamp ts) {
                ps.setTimestamp(index, ts);
            } else if (value instanceof Integer iv) {
                ps.setInt(index, iv);
            } else {
                ps.setString(index, Objects.toString(value, null));
            }
        }
    }

    private boolean blank(String text) {
        return text == null || text.isBlank();
    }
}
