package com.adaptwaf.controlplane.repository.jdbc;

import com.adaptwaf.controlplane.repository.PatternStateRepository;
import com.adaptwaf.controlplane.util.HashUtils;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import javax.sql.DataSource;

/**
 * 模式状态 JDBC 仓储实现。
 */
public class JdbcPatternStateRepository implements PatternStateRepository {

    private static final String UPSERT_SQL = """
            INSERT INTO waf_pattern_state (
                pattern_key_hash, pattern_key_text, pattern_state, first_seen, last_seen, hit_count, last_decision
            ) VALUES (?, ?, 'unknown', ?, ?, 1, ?)
            ON DUPLICATE KEY UPDATE
                last_seen = VALUES(last_seen),
                hit_count = hit_count + 1,
                last_decision = VALUES(last_decision),
                updated_at = CURRENT_TIMESTAMP(3)
            """;

    private static final String UPDATE_STATE_SQL = """
            UPDATE waf_pattern_state
            SET pattern_state = ?, updated_at = CURRENT_TIMESTAMP(3)
            WHERE pattern_key_hash = ?
            """;

    private static final String LOAD_RUNTIME_INDEX_SQL = """
            SELECT pattern_key_hash, pattern_state
            FROM waf_pattern_state
            WHERE pattern_state IN ('benign_confirmed', 'attack_confirmed')
            """;

    private final DataSource dataSource;

    public JdbcPatternStateRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public boolean upsertAndCheckFirstSeen(String patternKey, Instant eventTime, String decision) {
        String patternKeyHash = HashUtils.sha256Hex(patternKey.getBytes(StandardCharsets.UTF_8));
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(UPSERT_SQL)) {
            ps.setString(1, patternKeyHash);
            ps.setString(2, patternKey);
            ps.setTimestamp(3, Timestamp.from(eventTime));
            ps.setTimestamp(4, Timestamp.from(eventTime));
            ps.setString(5, decision);
            int affected = ps.executeUpdate();
            return affected == 1;
        } catch (Exception e) {
            throw new IllegalStateException("pattern_state_upsert_failed", e);
        }
    }

    @Override
    public void updatePatternState(String patternKey, String patternState) {
        String patternKeyHash = HashUtils.sha256Hex(patternKey.getBytes(StandardCharsets.UTF_8));
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(UPDATE_STATE_SQL)) {
            ps.setString(1, patternState);
            ps.setString(2, patternKeyHash);
            ps.executeUpdate();
        } catch (Exception e) {
            throw new IllegalStateException("pattern_state_update_failed", e);
        }
    }

    @Override
    public Map<String, String> loadRuntimePatternStateIndex() {
        Map<String, String> result = new HashMap<>();
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(LOAD_RUNTIME_INDEX_SQL);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                String key = rs.getString("pattern_key_hash");
                String state = rs.getString("pattern_state");
                if (key == null || key.isBlank() || state == null || state.isBlank()) {
                    continue;
                }
                result.put(key, state);
            }
            return result;
        } catch (Exception e) {
            throw new IllegalStateException("pattern_state_runtime_index_load_failed", e);
        }
    }
}
