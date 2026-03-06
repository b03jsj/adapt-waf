package com.adaptwaf.controlplane.repository.jdbc;

import com.adaptwaf.controlplane.model.CandidateQuery;
import com.adaptwaf.controlplane.model.ExemptionCandidate;
import com.adaptwaf.controlplane.model.PatternAggregateMetrics;
import com.adaptwaf.controlplane.repository.CandidateRepository;
import com.adaptwaf.controlplane.service.EntropyService;
import com.adaptwaf.controlplane.util.HashUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.sql.DataSource;

/**
 * 候选 JDBC 仓储实现。
 */
public class JdbcCandidateRepository implements CandidateRepository {

    private static final String INSERT_IF_ABSENT_SQL = """
            INSERT INTO waf_exemption_candidate (
                pattern_key_hash, pattern_key_text, candidate_status, candidate_reason, metrics_snapshot
            )
            SELECT ?, ?, 'auto_suggested', ?, CAST(? AS JSON)
            WHERE NOT EXISTS (
                SELECT 1
                FROM waf_exemption_candidate
                WHERE pattern_key_hash = ?
                  AND candidate_status IN ('auto_suggested', 'approved')
            )
            """;

    private static final String QUERY_BASE_SQL = """
            SELECT candidate_id, pattern_key_text AS pattern_key, candidate_status, candidate_reason, metrics_snapshot, created_at, updated_at
            FROM waf_exemption_candidate
            """;

    private static final String COUNT_BASE_SQL = """
            SELECT COUNT(1)
            FROM waf_exemption_candidate
            """;

    private static final String QUERY_BY_ID_SQL = """
            SELECT candidate_id, pattern_key_text AS pattern_key, candidate_status, candidate_reason, metrics_snapshot, created_at, updated_at
            FROM waf_exemption_candidate
            WHERE candidate_id = ?
            LIMIT 1
            """;

    private static final String CAS_STATUS_SQL = """
            UPDATE waf_exemption_candidate
            SET candidate_status = ?, updated_at = CURRENT_TIMESTAMP(3)
            WHERE candidate_id = ? AND candidate_status = ?
            """;

    private final DataSource dataSource;
    private final ObjectMapper objectMapper;

    public JdbcCandidateRepository(DataSource dataSource, ObjectMapper objectMapper) {
        this.dataSource = dataSource;
        this.objectMapper = objectMapper;
    }

    @Override
    public void upsertAutoSuggested(String patternKey, String reason, PatternAggregateMetrics metrics) {
        String patternKeyHash = HashUtils.sha256Hex(patternKey.getBytes(StandardCharsets.UTF_8));
        double entropyBits = EntropyService.shannonEntropyBits(metrics.ipHitCount());
        Map<String, Object> snapshot = new HashMap<>();
        snapshot.put("hits", metrics.hits());
        snapshot.put("ratio2xx", metrics.ratio2xx());
        snapshot.put("uniqueIp", metrics.uniqueIp());
        snapshot.put("singleIpRatio", metrics.singleIpRatio());
        snapshot.put("activeDays", metrics.activeDays());
        snapshot.put("peakDayRatio", metrics.peakDayRatio());
        snapshot.put("ipEntropyBits", entropyBits);
        snapshot.put("effectiveIpCount", EntropyService.effectiveCount(entropyBits));
        snapshot.put("ipHitCount", metrics.ipHitCount());

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(INSERT_IF_ABSENT_SQL)) {
            ps.setString(1, patternKeyHash);
            ps.setString(2, patternKey);
            ps.setString(3, reason);
            ps.setString(4, objectMapper.writeValueAsString(snapshot));
            ps.setString(5, patternKeyHash);
            ps.executeUpdate();
        } catch (Exception e) {
            throw new IllegalStateException("candidate_insert_failed", e);
        }
    }

    @Override
    public List<ExemptionCandidate> listByStatus(String status, int limit, int offset) {
        return list(new CandidateQuery(status, null, null, null, null), limit, offset);
    }

    @Override
    public List<ExemptionCandidate> list(CandidateQuery query, int limit, int offset) {
        CandidateQuery safeQuery = (query == null)
                ? new CandidateQuery("auto_suggested", null, null, null, null)
                : query;
        String status = (safeQuery.status() == null || safeQuery.status().isBlank())
                ? "auto_suggested"
                : safeQuery.status();

        int safeLimit = Math.max(1, Math.min(limit, 500));
        int safeOffset = Math.max(0, offset);
        List<ExemptionCandidate> result = new ArrayList<>(safeLimit);

        StringBuilder sql = new StringBuilder(QUERY_BASE_SQL);
        List<Object> params = new ArrayList<>();
        sql.append(" WHERE candidate_status = ?");
        params.add(status);

        if (!blank(safeQuery.reasonLike())) {
            sql.append(" AND candidate_reason LIKE ?");
            params.add("%" + safeQuery.reasonLike().trim() + "%");
        }
        if (!blank(safeQuery.patternKeyLike())) {
            sql.append(" AND pattern_key_text LIKE ?");
            params.add("%" + safeQuery.patternKeyLike().trim() + "%");
        }
        if (safeQuery.updatedFrom() != null) {
            sql.append(" AND updated_at >= ?");
            params.add(Timestamp.from(safeQuery.updatedFrom()));
        }
        if (safeQuery.updatedTo() != null) {
            sql.append(" AND updated_at < ?");
            params.add(Timestamp.from(safeQuery.updatedTo()));
        }
        sql.append(" ORDER BY updated_at DESC, candidate_id DESC LIMIT ? OFFSET ?");
        params.add(safeLimit);
        params.add(safeOffset);

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql.toString())) {
            bindParams(ps, params);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    result.add(mapRow(rs));
                }
            }
            return result;
        } catch (Exception e) {
            throw new IllegalStateException("candidate_query_failed", e);
        }
    }

    @Override
    public long count(CandidateQuery query) {
        CandidateQuery safeQuery = (query == null)
                ? new CandidateQuery("auto_suggested", null, null, null, null)
                : query;
        String status = (safeQuery.status() == null || safeQuery.status().isBlank())
                ? "auto_suggested"
                : safeQuery.status();

        StringBuilder sql = new StringBuilder(COUNT_BASE_SQL);
        List<Object> params = new ArrayList<>();
        sql.append(" WHERE candidate_status = ?");
        params.add(status);

        if (!blank(safeQuery.reasonLike())) {
            sql.append(" AND candidate_reason LIKE ?");
            params.add("%" + safeQuery.reasonLike().trim() + "%");
        }
        if (!blank(safeQuery.patternKeyLike())) {
            sql.append(" AND pattern_key_text LIKE ?");
            params.add("%" + safeQuery.patternKeyLike().trim() + "%");
        }
        if (safeQuery.updatedFrom() != null) {
            sql.append(" AND updated_at >= ?");
            params.add(Timestamp.from(safeQuery.updatedFrom()));
        }
        if (safeQuery.updatedTo() != null) {
            sql.append(" AND updated_at < ?");
            params.add(Timestamp.from(safeQuery.updatedTo()));
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
            throw new IllegalStateException("candidate_count_failed", e);
        }
    }

    @Override
    public ExemptionCandidate findById(long candidateId) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(QUERY_BY_ID_SQL)) {
            ps.setLong(1, candidateId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                return mapRow(rs);
            }
        } catch (Exception e) {
            throw new IllegalStateException("candidate_query_by_id_failed", e);
        }
    }

    @Override
    public boolean compareAndSetStatus(long candidateId, String fromStatus, String toStatus) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(CAS_STATUS_SQL)) {
            ps.setString(1, toStatus);
            ps.setLong(2, candidateId);
            ps.setString(3, fromStatus);
            return ps.executeUpdate() == 1;
        } catch (Exception e) {
            throw new IllegalStateException("candidate_update_status_failed", e);
        }
    }

    private ExemptionCandidate mapRow(ResultSet rs) throws Exception {
        Timestamp createdAt = rs.getTimestamp("created_at");
        Timestamp updatedAt = rs.getTimestamp("updated_at");
        return new ExemptionCandidate(
                rs.getLong("candidate_id"),
                rs.getString("pattern_key"),
                rs.getString("candidate_status"),
                rs.getString("candidate_reason"),
                rs.getString("metrics_snapshot"),
                createdAt == null ? Instant.EPOCH : createdAt.toInstant(),
                updatedAt == null ? Instant.EPOCH : updatedAt.toInstant()
        );
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
