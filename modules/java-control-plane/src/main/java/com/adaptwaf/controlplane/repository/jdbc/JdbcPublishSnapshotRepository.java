package com.adaptwaf.controlplane.repository.jdbc;

import com.adaptwaf.controlplane.model.ExemptionCompiledSnapshot;
import com.adaptwaf.controlplane.repository.PublishSnapshotRepository;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.sql.DataSource;

/**
 * 发布快照 JDBC 仓储实现。
 */
public class JdbcPublishSnapshotRepository implements PublishSnapshotRepository {

    private static final String INSERT_SQL = """
            INSERT INTO waf_exemption_publish_snapshot (
                publish_id, generation, sha256, compiled_content
            ) VALUES (?, ?, ?, ?)
            """;

    private static final String SELECT_BY_GENERATION_SQL = """
            SELECT publish_id, generation, sha256, compiled_content
            FROM waf_exemption_publish_snapshot
            WHERE generation = ?
            LIMIT 1
            """;

    private final DataSource dataSource;

    public JdbcPublishSnapshotRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public void saveSnapshot(ExemptionCompiledSnapshot snapshot) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(INSERT_SQL)) {
            ps.setString(1, snapshot.publishId());
            ps.setLong(2, snapshot.generation());
            ps.setString(3, snapshot.sha256());
            ps.setBytes(4, snapshot.content());
            ps.executeUpdate();
        } catch (Exception e) {
            throw new IllegalStateException("publish_snapshot_save_failed", e);
        }
    }

    @Override
    public ExemptionCompiledSnapshot findByGeneration(long generation) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(SELECT_BY_GENERATION_SQL)) {
            ps.setLong(1, generation);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                return new ExemptionCompiledSnapshot(
                        rs.getLong("generation"),
                        rs.getString("publish_id"),
                        rs.getString("sha256"),
                        rs.getBytes("compiled_content")
                );
            }
        } catch (Exception e) {
            throw new IllegalStateException("publish_snapshot_query_failed", e);
        }
    }
}
