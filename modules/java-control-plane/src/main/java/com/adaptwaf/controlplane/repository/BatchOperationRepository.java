package com.adaptwaf.controlplane.repository;

import com.adaptwaf.controlplane.model.BatchOperation;
import com.adaptwaf.controlplane.model.BatchOperationItem;
import java.util.List;

/**
 * 批量审核任务仓储接口。
 */
public interface BatchOperationRepository {

    /**
     * 创建批量任务。
     *
     * @param operationId 任务 ID
     * @param operationType 任务类型（approve/reject）
     * @param operator 操作人
     * @param reason 原因
     * @param ticketId 工单号
     * @param requestedScope 请求 scope
     * @param requestedPatternState 请求状态
     * @param totalCount 总条数
     */
    void createOperation(
            String operationId,
            String operationType,
            String operator,
            String reason,
            String ticketId,
            String requestedScope,
            String requestedPatternState,
            int totalCount
    );

    /**
     * 保存单条执行结果。
     *
     * @param operationId 任务 ID
     * @param candidateId 候选 ID
     * @param success 是否成功
     * @param exemptionId 豁免 ID
     * @param matchScope 匹配范围
     * @param error 失败错误
     */
    void insertItem(
            String operationId,
            long candidateId,
            boolean success,
            String exemptionId,
            String matchScope,
            String error
    );

    /**
     * 更新任务收尾状态。
     *
     * @param operationId 任务 ID
     * @param successCount 成功数
     * @param failedCount 失败数
     * @param status 最终状态
     */
    void finishOperation(
            String operationId,
            int successCount,
            int failedCount,
            String status
    );

    /**
     * 查询任务。
     *
     * @param operationId 任务 ID
     * @return 任务，不存在返回 null
     */
    BatchOperation findOperation(String operationId);

    /**
     * 查询任务明细。
     *
     * @param operationId 任务 ID
     * @param limit 条数
     * @param offset 偏移
     * @return 明细列表
     */
    List<BatchOperationItem> listItems(String operationId, int limit, int offset);

    /**
     * 按状态查询批量任务。
     *
     * @param status 任务状态，可为空
     * @param limit 条数
     * @param offset 偏移
     * @return 任务列表
     */
    List<BatchOperation> listOperations(String status, int limit, int offset);

    /**
     * 统计批量任务数量。
     *
     * @param status 状态，可为空
     * @return 总数
     */
    long countOperations(String status);
}
