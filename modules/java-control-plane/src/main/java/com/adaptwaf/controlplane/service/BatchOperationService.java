package com.adaptwaf.controlplane.service;

import com.adaptwaf.controlplane.model.BatchOperation;
import com.adaptwaf.controlplane.model.BatchOperationItem;
import com.adaptwaf.controlplane.repository.BatchOperationRepository;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 批量审核异步任务服务。
 */
public class BatchOperationService {

    private final ReviewWorkflowService reviewWorkflowService;
    private final BatchOperationRepository batchOperationRepository;
    private final ExecutorService executorService;

    public BatchOperationService(
            ReviewWorkflowService reviewWorkflowService,
            BatchOperationRepository batchOperationRepository,
            int workerThreads
    ) {
        this.reviewWorkflowService = reviewWorkflowService;
        this.batchOperationRepository = batchOperationRepository;
        int threads = Math.max(1, workerThreads);
        this.executorService = Executors.newFixedThreadPool(threads);
    }

    /**
     * 提交异步批量审批任务。
     *
     * @param candidateIds 候选 ID 列表
     * @param operator 操作人
     * @param reason 原因
     * @param ticketId 工单号
     * @param matchScope 匹配范围
     * @param expiresAt 过期时间
     * @return 任务 ID
     */
    public String submitApprove(
            List<Long> candidateIds,
            String operator,
            String reason,
            String ticketId,
            String matchScope,
            String expiresAt
    ) {
        String operationId = buildOperationId("approve");
        batchOperationRepository.createOperation(
                operationId,
                "approve",
                operator,
                reason,
                ticketId,
                matchScope,
                null,
                candidateIds.size()
        );
        executorService.submit(() -> runApprove(operationId, candidateIds, operator, reason, ticketId, matchScope, expiresAt));
        return operationId;
    }

    /**
     * 提交异步批量拒绝任务。
     *
     * @param candidateIds 候选 ID 列表
     * @param operator 操作人
     * @param reason 原因
     * @param ticketId 工单号
     * @param patternState 目标模式状态
     * @return 任务 ID
     */
    public String submitReject(
            List<Long> candidateIds,
            String operator,
            String reason,
            String ticketId,
            String patternState
    ) {
        String operationId = buildOperationId("reject");
        batchOperationRepository.createOperation(
                operationId,
                "reject",
                operator,
                reason,
                ticketId,
                null,
                patternState,
                candidateIds.size()
        );
        executorService.submit(() -> runReject(operationId, candidateIds, operator, reason, ticketId, patternState));
        return operationId;
    }

    /**
     * 查询批量任务状态。
     *
     * @param operationId 任务 ID
     * @return 任务
     */
    public BatchOperation getOperation(String operationId) {
        return batchOperationRepository.findOperation(operationId);
    }

    /**
     * 查询批量任务明细。
     *
     * @param operationId 任务 ID
     * @param limit 条数
     * @param offset 偏移
     * @return 明细列表
     */
    public List<BatchOperationItem> listItems(String operationId, int limit, int offset) {
        return batchOperationRepository.listItems(operationId, limit, offset);
    }

    /**
     * 查询批量任务列表。
     *
     * @param status 状态，可为空
     * @param limit 条数
     * @param offset 偏移
     * @return 任务列表
     */
    public List<BatchOperation> listOperations(String status, int limit, int offset) {
        return batchOperationRepository.listOperations(status, limit, offset);
    }

    /**
     * 统计批量任务总量。
     *
     * @param status 状态，可为空
     * @return 总量
     */
    public long countOperations(String status) {
        return batchOperationRepository.countOperations(status);
    }

    private void runApprove(
            String operationId,
            List<Long> candidateIds,
            String operator,
            String reason,
            String ticketId,
            String matchScope,
            String expiresAt
    ) {
        int successCount = 0;
        int failedCount = 0;
        for (Long candidateId : candidateIds) {
            try {
                ReviewWorkflowService.ApprovalResult result = reviewWorkflowService.approveCandidate(
                        candidateId,
                        operator,
                        reason,
                        ticketId,
                        matchScope,
                        expiresAt
                );
                batchOperationRepository.insertItem(
                        operationId,
                        candidateId,
                        true,
                        result.exemptionId(),
                        result.matchScope(),
                        null
                );
                successCount++;
            } catch (Exception e) {
                batchOperationRepository.insertItem(
                        operationId,
                        candidateId,
                        false,
                        null,
                        null,
                        e.getMessage()
                );
                failedCount++;
            }
        }
        batchOperationRepository.finishOperation(
                operationId,
                successCount,
                failedCount,
                resolveFinalStatus(successCount, failedCount)
        );
    }

    private void runReject(
            String operationId,
            List<Long> candidateIds,
            String operator,
            String reason,
            String ticketId,
            String patternState
    ) {
        int successCount = 0;
        int failedCount = 0;
        for (Long candidateId : candidateIds) {
            try {
                reviewWorkflowService.rejectCandidate(
                        candidateId,
                        operator,
                        reason,
                        ticketId,
                        patternState
                );
                batchOperationRepository.insertItem(
                        operationId,
                        candidateId,
                        true,
                        null,
                        null,
                        null
                );
                successCount++;
            } catch (Exception e) {
                batchOperationRepository.insertItem(
                        operationId,
                        candidateId,
                        false,
                        null,
                        null,
                        e.getMessage()
                );
                failedCount++;
            }
        }
        batchOperationRepository.finishOperation(
                operationId,
                successCount,
                failedCount,
                resolveFinalStatus(successCount, failedCount)
        );
    }

    private String buildOperationId(String prefix) {
        return "op_" + prefix + "_" + UUID.randomUUID().toString().replace("-", "");
    }

    private String resolveFinalStatus(int successCount, int failedCount) {
        if (failedCount == 0) {
            return "success";
        }
        if (successCount == 0) {
            return "failed";
        }
        return "partial_success";
    }
}
