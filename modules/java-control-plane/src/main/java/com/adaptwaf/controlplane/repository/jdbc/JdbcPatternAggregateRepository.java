package com.adaptwaf.controlplane.repository.jdbc;

import com.adaptwaf.controlplane.model.PatternAggregateMetrics;
import com.adaptwaf.controlplane.repository.PatternAggregateRepository;
import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;

/**
 * 模式聚合 JDBC 仓储实现。
 */
public class JdbcPatternAggregateRepository implements PatternAggregateRepository {

    private static final String QUERY_SQL = """
            SELECT
                waf_alert_event.pattern_key_text,
                waf_alert_event.client_ip,
                waf_alert_event.event_date,
                COUNT(*) AS ip_day_hits,
                SUM(CASE WHEN waf_alert_event.status_code BETWEEN 200 AND 299 THEN 1 ELSE 0 END) AS ip_day_2xx_hits
            FROM waf_alert_event
            LEFT JOIN waf_pattern_state ps ON ps.pattern_key_hash = waf_alert_event.pattern_key_hash
            WHERE waf_alert_event.event_time >= ? AND waf_alert_event.event_time < ?
              AND waf_alert_event.detector IN ('libinjection_sqli', 'libinjection_xss')
              AND waf_alert_event.policy_decision_basis LIKE 'parser_hit_%'
              AND waf_alert_event.exemption_applied = 0
              AND (ps.pattern_state IS NULL OR ps.pattern_state = 'unknown')
            GROUP BY waf_alert_event.pattern_key_text, waf_alert_event.client_ip, waf_alert_event.event_date
            """;

    private final DataSource dataSource;

    public JdbcPatternAggregateRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public List<PatternAggregateMetrics> queryWindow(Instant fromInclusive, Instant toExclusive) {
        Map<String, MutableAggregate> aggregateMap = new HashMap<>();

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(QUERY_SQL)) {
            ps.setTimestamp(1, Timestamp.from(fromInclusive));
            ps.setTimestamp(2, Timestamp.from(toExclusive));

            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String patternKey = rs.getString("pattern_key_text");
                    String clientIp = rs.getString("client_ip");
                    Date eventDateRaw = rs.getDate("event_date");
                    LocalDate eventDate = eventDateRaw == null ? null : eventDateRaw.toLocalDate();
                    long ipDayHits = rs.getLong("ip_day_hits");
                    long ipDay2xxHits = rs.getLong("ip_day_2xx_hits");

                    MutableAggregate aggregate = aggregateMap.computeIfAbsent(patternKey, MutableAggregate::new);
                    aggregate.hits += ipDayHits;
                    aggregate.successHits += ipDay2xxHits;
                    long mergedIpHits = aggregate.ipHitCount.getOrDefault(clientIp, 0L) + ipDayHits;
                    aggregate.maxIpHits = Math.max(aggregate.maxIpHits, mergedIpHits);
                    aggregate.ipHitCount.put(clientIp, mergedIpHits);
                    if (eventDate != null) {
                        aggregate.dayHitCount.merge(eventDate, ipDayHits, Long::sum);
                    }
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException("pattern_aggregate_query_failed", e);
        }

        List<PatternAggregateMetrics> result = new ArrayList<>(aggregateMap.size());
        for (MutableAggregate aggregate : aggregateMap.values()) {
            double ratio2xx = aggregate.hits == 0 ? 0D : ((double) aggregate.successHits / (double) aggregate.hits);
            double singleIpRatio = aggregate.hits == 0 ? 0D : ((double) aggregate.maxIpHits / (double) aggregate.hits);
            int activeDays = aggregate.dayHitCount.size();
            long peakDayHits = aggregate.dayHitCount.values().stream().mapToLong(Long::longValue).max().orElse(0L);
            double peakDayRatio = aggregate.hits == 0 ? 0D : ((double) peakDayHits / (double) aggregate.hits);
            result.add(new PatternAggregateMetrics(
                    aggregate.patternKey,
                    aggregate.hits,
                    ratio2xx,
                    aggregate.ipHitCount.size(),
                    singleIpRatio,
                    activeDays,
                    peakDayRatio,
                    aggregate.ipHitCount
            ));
        }
        return result;
    }

    /**
     * 聚合过程中的可变对象。
     */
    private static final class MutableAggregate {
        private final String patternKey;
        private final Map<String, Long> ipHitCount = new HashMap<>();
        private final Map<LocalDate, Long> dayHitCount = new HashMap<>();
        private long hits = 0;
        private long successHits = 0;
        private long maxIpHits = 0;

        private MutableAggregate(String patternKey) {
            this.patternKey = patternKey;
        }
    }
}
