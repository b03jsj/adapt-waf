package com.adaptwaf.controlplane.repository;

import com.adaptwaf.controlplane.model.PatternAggregateMetrics;
import java.time.Instant;
import java.util.List;

/**
 * 模式聚合查询仓储接口。
 */
public interface PatternAggregateRepository {

    /**
     * 查询时间窗口内的模式聚合统计。
     *
     * @param fromInclusive 起始时间（含）
     * @param toExclusive 结束时间（不含）
     * @return 模式聚合结果
     */
    List<PatternAggregateMetrics> queryWindow(Instant fromInclusive, Instant toExclusive);
}
