package com.adaptwaf.controlplane.repository.jdbc;

import com.adaptwaf.controlplane.model.BatchOperation;
import com.adaptwaf.controlplane.model.BatchOperationItem;
import com.adaptwaf.controlplane.repository.BatchOperationRepository;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;

/**
 * 批量审核任务 JDBC 仓储实现。
 */
public class JdbcBatchOperationRepository implements BatchOperationRepository {

    private static final String INSERT_OPERATION_SQL = """
            INSERT INTO waf_batch_operation (
                operation_id, operation_type, status, operator, reason, ticket_id,
                requested_scope, requested_pattern_state, total_count, success_count, failed_count
            ) VALUES (?, ?, 'running', ?, ?, ?, ?, ?, ?, 0, 0)
            """;

    private static final String INSERT_ITEM_SQL = """
            INSERT INTO waf_batch_operation_item (
                operation_id, candidate_id, success, exemption_id, match_scope, error
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                success = VALUES(success),
                exemption_id = VALUES(exemption_id),
                match_scope = VALUES(match_scope),
                error = VALUES(error)
            """;

    private static final String FINISH_OPERATION_SQL = """
            UPDATE waf_batch_operation
            SET success_count = ?, failed_count = ?, status = ?, updated_at = CURRENT_TIMESTAMP(3)
            WHERE operation_id = ?
            """;

    private static final String QUERY_OPERATION_SQL = """
            SELECT
                operation_id, operation_type, status, operator, reason, ticket_id,
                requested_scope, requested_pattern_state, total_count, success_count, failed_count,
                created_at, updated_at
            FROM waf_batch_operation
            WHERE operation_id = ?
            LIMIT 1
            """;

    private static final String QUERY_ITEM_SQL = """
            SELECT id, operation_id, candidate_id, success, exemption_id, match_scope, error, created_at
            FROM waf_batch_operation_item
            WHERE operation_id = ?
            ORDER BY id ASC
            LIMIT ? OFFSET ?
            """;

    private static final String QUERY_OPERATION_LIST_BASE_SQL = """
            SELECT
                operation_id, operation_type, status, operator, reason, ticket_id,
                requested_scope, requested_pattern_state, total_count, success_count, failed_count,
                created_at, updated_at
            FROM waf_batch_operation
            """;

    private static final String COUNT_OPERATION_BASE_SQL = """
            SELECT COUNT(1)
            FROM waf_batch_operation
            """;

    private final DataSource dataSource;

    public JdbcBatchOperationRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public void createOperation(
            String operationId,
            String operationType,
            String operator,
            String reason,
            String ticketId,
            String requestedScope,
            String requestedPatternState,
            int totalCount
    ) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(INSERT_OPERATION_SQL)) {
            ps.setString(1, operationId);
            ps.setString(2, operationType);
            ps.setString(3, operator);
            ps.setString(4, reason);
            ps.setString(5, ticketId);
            ps.setString(6, requestedScope);
            ps.setString(7, requestedPatternState);
            ps.setInt(8, totalCount);
            ps.executeUpdate();
        } catch (Exception e) {
            throw new IllegalStateException("batch_operation_create_failed", e);
        }
    }

    @Override
    public void insertItem(
            String operationId,
            long candidateId,
            boolean success,
            String exemptionId,
            String matchScope,
            String error
    ) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(INSERT_ITEM_SQL)) {
            ps.setString(1, operationId);
            ps.setLong(2, candidateId);
            ps.setBoolean(3, success);
            ps.setString(4, exemptionId);
            ps.setString(5, matchScope);
            ps.setString(6, error);
            ps.executeUpdate();
        } catch (Exception e) {
            throw new IllegalStateException("batch_operation_item_insert_failed", e);
        }
    }

    @Override
    public void finishOperation(
            String operationId,
            int successCount,
            int failedCount,
            String status
    ) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(FINISH_OPERATION_SQL)) {
            ps.setInt(1, successCount);
            ps.setInt(2, failedCount);
            ps.setString(3, status);
            ps.setString(4, operationId);
            ps.executeUpdate();
        } catch (Exception e) {
            throw new IllegalStateException("batch_operation_finish_failed", e);
        }
    }

    @Override
    public BatchOperation findOperation(String operationId) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(QUERY_OPERATION_SQL)) {
            ps.setString(1, operationId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                Timestamp createdAt = rs.getTimestamp("created_at");
                Timestamp updatedAt = rs.getTimestamp("updated_at");
                return new BatchOperation(
                        rs.getString("operation_id"),
                        rs.getString("operation_type"),
                        rs.getString("status"),
                        rs.getString("operator"),
                        rs.getString("reason"),
                        rs.getString("ticket_id"),
                        rs.getString("requested_scope"),
                        rs.getString("requested_pattern_state"),
                        rs.getInt("total_count"),
                        rs.getInt("success_count"),
                        rs.getInt("failed_count"),
                        createdAt == null ? Instant.EPOCH : createdAt.toInstant(),
                        updatedAt == null ? Instant.EPOCH : updatedAt.toInstant()
                );
            }
        } catch (Exception e) {
            throw new IllegalStateException("batch_operation_query_failed", e);
        }
    }

    @Override
    public List<BatchOperationItem> listItems(String operationId, int limit, int offset) {
        int safeLimit = Math.max(1, Math.min(limit, 2000));
        int safeOffset = Math.max(0, offset);
        List<BatchOperationItem> items = new ArrayList<>(safeLimit);
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(QUERY_ITEM_SQL)) {
            ps.setString(1, operationId);
            ps.setInt(2, safeLimit);
            ps.setInt(3, safeOffset);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Timestamp createdAt = rs.getTimestamp("created_at");
                    items.add(new BatchOperationItem(
                            rs.getLong("id"),
                            rs.getString("operation_id"),
                            rs.getLong("candidate_id"),
                            rs.getBoolean("success"),
                            rs.getString("exemption_id"),
                            rs.getString("match_scope"),
                            rs.getString("error"),
                            createdAt == null ? Instant.EPOCH : createdAt.toInstant()
                    ));
                }
            }
            return items;
        } catch (Exception e) {
            throw new IllegalStateException("batch_operation_items_query_failed", e);
        }
    }

    @Override
    public List<BatchOperation> listOperations(String status, int limit, int offset) {
        int safeLimit = Math.max(1, Math.min(limit, 500));
        int safeOffset = Math.max(0, offset);
        String safeStatus = (status == null || status.isBlank()) ? null : status;
        List<BatchOperation> operations = new ArrayList<>(safeLimit);

        StringBuilder sql = new StringBuilder(QUERY_OPERATION_LIST_BASE_SQL);
        if (safeStatus != null) {
            sql.append(" WHERE status = ?");
        }
        sql.append(" ORDER BY created_at DESC, operation_id DESC LIMIT ? OFFSET ?");

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
                    operations.add(new BatchOperation(
                            rs.getString("operation_id"),
                            rs.getString("operation_type"),
                            rs.getString("status"),
                            rs.getString("operator"),
                            rs.getString("reason"),
                            rs.getString("ticket_id"),
                            rs.getString("requested_scope"),
                            rs.getString("requested_pattern_state"),
                            rs.getInt("total_count"),
                            rs.getInt("success_count"),
                            rs.getInt("failed_count"),
                            createdAt == null ? Instant.EPOCH : createdAt.toInstant(),
                            updatedAt == null ? Instant.EPOCH : updatedAt.toInstant()
                    ));
                }
            }
            return operations;
        } catch (Exception e) {
            throw new IllegalStateException("batch_operation_list_query_failed", e);
        }
    }

    @Override
    public long countOperations(String status) {
        String safeStatus = (status == null || status.isBlank()) ? null : status;
        StringBuilder sql = new StringBuilder(COUNT_OPERATION_BASE_SQL);
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
            throw new IllegalStateException("batch_operation_count_failed", e);
        }
    }
}
