package com.adaptwaf.controlplane.repository.jdbc;

import com.adaptwaf.controlplane.model.NodePublishResult;
import com.adaptwaf.controlplane.model.PublishNodeResult;
import com.adaptwaf.controlplane.model.PublishRecord;
import com.adaptwaf.controlplane.repository.PublishRepository;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;

/**
 * 发布状态 JDBC 仓储实现。
 */
public class JdbcPublishRepository implements PublishRepository {

    private static final String INSERT_PUBLISH_SQL = """
            INSERT INTO waf_exemption_publish (
                publish_id, generation, sha256, operator, reason, status
            ) VALUES (?, ?, ?, ?, ?, 'running')
            """;

    private static final String UPSERT_NODE_SQL = """
            INSERT INTO waf_exemption_publish_node_result (
                publish_id, node_id, node_status, current_generation, last_error
            ) VALUES (?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                node_status = VALUES(node_status),
                current_generation = VALUES(current_generation),
                last_error = VALUES(last_error),
                updated_at = CURRENT_TIMESTAMP(3)
            """;

    private static final String UPDATE_PUBLISH_STATUS_SQL = """
            UPDATE waf_exemption_publish
            SET status = ?, updated_at = CURRENT_TIMESTAMP(3)
            WHERE publish_id = ?
            """;

    private static final String QUERY_NODE_RESULTS_SQL = """
            SELECT publish_id, node_id, node_status, current_generation, last_error, updated_at
            FROM waf_exemption_publish_node_result
            WHERE publish_id = ?
            ORDER BY node_id ASC
            """;

    private static final String QUERY_PUBLISH_SQL = """
            SELECT
                publish_id, generation, sha256, operator, reason, status, created_at, updated_at
            FROM waf_exemption_publish
            """;

    private static final String COUNT_PUBLISH_BASE_SQL = """
            SELECT COUNT(1)
            FROM waf_exemption_publish
            """;

    private final DataSource dataSource;

    public JdbcPublishRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public void createPublish(String publishId, long generation, String sha256, String operator, String reason) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(INSERT_PUBLISH_SQL)) {
            ps.setString(1, publishId);
            ps.setLong(2, generation);
            ps.setString(3, sha256);
            ps.setString(4, operator);
            ps.setString(5, reason);
            ps.executeUpdate();
        } catch (Exception e) {
            throw new IllegalStateException("publish_create_failed", e);
        }
    }

    @Override
    public void saveNodeResult(String publishId, NodePublishResult result) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(UPSERT_NODE_SQL)) {
            ps.setString(1, publishId);
            ps.setString(2, result.nodeId());
            ps.setString(3, result.success() ? "success" : "failed");
            ps.setLong(4, result.currentGeneration());
            ps.setString(5, result.lastError());
            ps.executeUpdate();
        } catch (Exception e) {
            throw new IllegalStateException("publish_node_result_save_failed", e);
        }
    }

    @Override
    public void updatePublishStatus(String publishId, String status) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(UPDATE_PUBLISH_STATUS_SQL)) {
            ps.setString(1, status);
            ps.setString(2, publishId);
            ps.executeUpdate();
        } catch (Exception e) {
            throw new IllegalStateException("publish_status_update_failed", e);
        }
    }

    @Override
    public List<PublishNodeResult> listNodeResults(String publishId) {
        List<PublishNodeResult> results = new ArrayList<>();
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(QUERY_NODE_RESULTS_SQL)) {
            ps.setString(1, publishId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Timestamp updatedAt = rs.getTimestamp("updated_at");
                    results.add(new PublishNodeResult(
                            rs.getString("publish_id"),
                            rs.getString("node_id"),
                            rs.getString("node_status"),
                            rs.getLong("current_generation"),
                            rs.getString("last_error"),
                            updatedAt == null ? Instant.EPOCH : updatedAt.toInstant()
                    ));
                }
            }
            return results;
        } catch (Exception e) {
            throw new IllegalStateException("publish_node_results_query_failed", e);
        }
    }

    @Override
    public List<PublishRecord> listPublishes(int limit, int offset) {
        return listPublishes(null, limit, offset);
    }

    @Override
    public List<PublishRecord> listPublishes(String status, int limit, int offset) {
        int safeLimit = Math.max(1, Math.min(limit, 500));
        int safeOffset = Math.max(offset, 0);
        String safeStatus = (status == null || status.isBlank()) ? null : status;
        List<PublishRecord> records = new ArrayList<>(safeLimit);
        StringBuilder sql = new StringBuilder(QUERY_PUBLISH_SQL);
        if (safeStatus != null) {
            sql.append(" WHERE status = ?");
        }
        sql.append(" ORDER BY created_at DESC, publish_id DESC LIMIT ? OFFSET ?");

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql.toString())) {
            int i = 1;
            if (safeStatus != null) {
                ps.setString(i++, safeStatus);
            }
            ps.setInt(i++, safeLimit);
            ps.setInt(i, safeOffset);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Timestamp createdAt = rs.getTimestamp("created_at");
                    Timestamp updatedAt = rs.getTimestamp("updated_at");
                    records.add(new PublishRecord(
                            rs.getString("publish_id"),
                            rs.getLong("generation"),
                            rs.getString("sha256"),
                            rs.getString("operator"),
                            rs.getString("reason"),
                            rs.getString("status"),
                            createdAt == null ? Instant.EPOCH : createdAt.toInstant(),
                            updatedAt == null ? Instant.EPOCH : updatedAt.toInstant()
                    ));
                }
            }
            return records;
        } catch (Exception e) {
            throw new IllegalStateException("publish_list_query_failed", e);
        }
    }

    @Override
    public long countPublishes(String status) {
        String safeStatus = (status == null || status.isBlank()) ? null : status;
        StringBuilder sql = new StringBuilder(COUNT_PUBLISH_BASE_SQL);
        if (safeStatus != null) {
            sql.append(" WHERE status = ?");
        }

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql.toString())) {
            if (safeStatus != null) {
                ps.setString(1, safeStatus);
            }
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getLong(1);
                }
                return 0L;
            }
        } catch (Exception e) {
            throw new IllegalStateException("publish_count_query_failed", e);
        }
    }
}
