package com.adaptwaf.controlplane.repository;

import com.adaptwaf.controlplane.model.PatternAggregateMetrics;
import com.adaptwaf.controlplane.model.ExemptionCandidate;
import com.adaptwaf.controlplane.model.CandidateQuery;
import java.util.List;

/**
 * 候选管理仓储接口。
 */
public interface CandidateRepository {

    /**
     * 写入或更新自动建议候选。
     *
     * @param patternKey 模式键
     * @param reason 候选原因
     * @param metrics 聚合统计快照
     */
    void upsertAutoSuggested(String patternKey, String reason, PatternAggregateMetrics metrics);

    /**
     * 按状态查询候选列表。
     *
     * @param status 候选状态
     * @param limit 限制条数
     * @param offset 偏移量
     * @return 候选列表
     */
    List<ExemptionCandidate> listByStatus(String status, int limit, int offset);

    /**
     * 按筛选条件查询候选列表。
     *
     * @param query 条件
     * @param limit 限制条数
     * @param offset 偏移量
     * @return 候选列表
     */
    List<ExemptionCandidate> list(CandidateQuery query, int limit, int offset);

    /**
     * 统计候选总数。
     *
     * @param query 条件
     * @return 总数
     */
    long count(CandidateQuery query);

    /**
     * 按主键查询候选。
     *
     * @param candidateId 候选 ID
     * @return 候选，未找到返回 null
     */
    ExemptionCandidate findById(long candidateId);

    /**
     * 更新候选状态。
     *
     * @param candidateId 候选 ID
     * @param fromStatus 原状态
     * @param toStatus 新状态
     * @return true 表示更新成功
     */
    boolean compareAndSetStatus(long candidateId, String fromStatus, String toStatus);
}
