package com.adaptwaf.controlplane.repository.jdbc;

import com.adaptwaf.controlplane.model.ReviewAuditRecord;
import com.adaptwaf.controlplane.repository.ReviewAuditRepository;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;

/**
 * 审核审计 JDBC 仓储实现。
 */
public class JdbcReviewAuditRepository implements ReviewAuditRepository {

    private static final String INSERT_SQL = """
            INSERT INTO waf_review_audit (
                operator, action, target_type, target_id, before_json, after_json, reason, ticket_id
            ) VALUES (?, ?, ?, ?, CAST(? AS JSON), CAST(? AS JSON), ?, ?)
            """;

    private static final String QUERY_SQL = """
            SELECT
                audit_id, operator, action, target_type, target_id,
                before_json, after_json, reason, ticket_id, created_at
            FROM waf_review_audit
            ORDER BY created_at DESC, audit_id DESC
            LIMIT ? OFFSET ?
            """;

    private static final String COUNT_SQL = """
            SELECT COUNT(1)
            FROM waf_review_audit
            """;

    private final DataSource dataSource;

    public JdbcReviewAuditRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public void append(
            String operator,
            String action,
            String targetType,
            String targetId,
            String beforeJson,
            String afterJson,
            String reason,
            String ticketId
    ) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(INSERT_SQL)) {
            ps.setString(1, operator);
            ps.setString(2, action);
            ps.setString(3, targetType);
            ps.setString(4, targetId);
            ps.setString(5, safeJson(beforeJson));
            ps.setString(6, safeJson(afterJson));
            ps.setString(7, reason == null ? "-" : reason);
            ps.setString(8, (ticketId == null || ticketId.isBlank()) ? null : ticketId);
            ps.executeUpdate();
        } catch (Exception e) {
            throw new IllegalStateException("review_audit_insert_failed", e);
        }
    }

    @Override
    public List<ReviewAuditRecord> list(int limit, int offset) {
        int safeLimit = Math.max(1, Math.min(limit, 500));
        int safeOffset = Math.max(0, offset);
        List<ReviewAuditRecord> result = new ArrayList<>(safeLimit);

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(QUERY_SQL)) {
            ps.setInt(1, safeLimit);
            ps.setInt(2, safeOffset);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Timestamp createdAt = rs.getTimestamp("created_at");
                    result.add(new ReviewAuditRecord(
                            rs.getLong("audit_id"),
                            rs.getString("operator"),
                            rs.getString("action"),
                            rs.getString("target_type"),
                            rs.getString("target_id"),
                            rs.getString("before_json"),
                            rs.getString("after_json"),
                            rs.getString("reason"),
                            rs.getString("ticket_id"),
                            createdAt == null ? Instant.EPOCH : createdAt.toInstant()
                    ));
                }
            }
            return result;
        } catch (Exception e) {
            throw new IllegalStateException("review_audit_query_failed", e);
        }
    }

    @Override
    public long count() {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(COUNT_SQL);
             ResultSet rs = ps.executeQuery()) {
            if (rs.next()) {
                return rs.getLong(1);
            }
            return 0L;
        } catch (Exception e) {
            throw new IllegalStateException("review_audit_count_failed", e);
        }
    }

    private String safeJson(String raw) {
        if (raw == null || raw.isBlank()) {
            return "{}";
        }
        return raw;
    }
}
