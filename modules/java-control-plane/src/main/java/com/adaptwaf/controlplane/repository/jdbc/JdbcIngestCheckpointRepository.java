package com.adaptwaf.controlplane.repository.jdbc;

import com.adaptwaf.controlplane.repository.IngestCheckpointRepository;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.sql.DataSource;

/**
 * 采集位点 JDBC 仓储实现。
 */
public class JdbcIngestCheckpointRepository implements IngestCheckpointRepository {

    private static final String SELECT_SQL = """
            SELECT offset_bytes
            FROM waf_ingest_checkpoint
            WHERE source_node = ? AND file_path = ?
            """;

    private static final String UPSERT_SQL = """
            INSERT INTO waf_ingest_checkpoint (source_node, file_path, inode, offset_bytes)
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                inode = VALUES(inode),
                offset_bytes = VALUES(offset_bytes),
                updated_at = CURRENT_TIMESTAMP(3)
            """;

    private final DataSource dataSource;

    public JdbcIngestCheckpointRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public long getOffset(String sourceNode, String filePath) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(SELECT_SQL)) {
            ps.setString(1, sourceNode);
            ps.setString(2, filePath);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getLong(1);
                }
            }
            return 0L;
        } catch (Exception e) {
            throw new IllegalStateException("checkpoint_select_failed", e);
        }
    }

    @Override
    public void saveOffset(String sourceNode, String filePath, long inode, long offsetBytes) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(UPSERT_SQL)) {
            ps.setString(1, sourceNode);
            ps.setString(2, filePath);
            ps.setLong(3, inode);
            ps.setLong(4, offsetBytes);
            ps.executeUpdate();
        } catch (Exception e) {
            throw new IllegalStateException("checkpoint_upsert_failed", e);
        }
    }
}
