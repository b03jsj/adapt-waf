package com.adaptwaf.controlplane.publish;

import com.adaptwaf.controlplane.model.ExemptionCompiledSnapshot;
import com.adaptwaf.controlplane.model.NodePublishResult;
import com.adaptwaf.controlplane.repository.PublishRepository;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 豁免发布编排服务。
 */
public class PublishCoordinator {

    private final OpenRestyAdminClient adminClient;
    private final PublishRepository publishRepository;
    private final int maxAttempts;
    private final long retryIntervalMillis;

    public PublishCoordinator(
            OpenRestyAdminClient adminClient,
            PublishRepository publishRepository,
            int maxAttempts,
            long retryIntervalMillis
    ) {
        this.adminClient = adminClient;
        this.publishRepository = publishRepository;
        this.maxAttempts = Math.max(1, maxAttempts);
        this.retryIntervalMillis = Math.max(0L, retryIntervalMillis);
    }

    /**
     * 推送快照到所有节点，并进行失败重试和代次收敛检查。
     *
     * @param snapshot 快照
     * @param nodeIds 节点列表
     * @param operator 操作人
     * @param reason 发布原因
     * @return 各节点最终结果
     */
    public List<NodePublishResult> publishAll(
            ExemptionCompiledSnapshot snapshot,
            List<String> nodeIds,
            String operator,
            String reason
    ) {
        publishRepository.createPublish(
                snapshot.publishId(),
                snapshot.generation(),
                snapshot.sha256(),
                operator,
                reason
        );

        Map<String, NodePublishResult> latest = new LinkedHashMap<>();
        Set<String> pending = new LinkedHashSet<>(nodeIds);

        for (int round = 1; round <= maxAttempts && !pending.isEmpty(); round++) {
            Set<String> toPublish = new LinkedHashSet<>(pending);
            for (String nodeId : toPublish) {
                NodePublishResult result = adminClient.publish(nodeId, snapshot);
                latest.put(nodeId, result);
                publishRepository.saveNodeResult(snapshot.publishId(), result);
            }

            pending = checkConvergence(snapshot.publishId(), snapshot.generation(), nodeIds, latest);
            if (!pending.isEmpty() && round < maxAttempts && retryIntervalMillis > 0) {
                sleepQuietly(retryIntervalMillis);
            }
        }

        List<NodePublishResult> finalResults = new ArrayList<>(nodeIds.size());
        int successCount = 0;
        for (String nodeId : nodeIds) {
            NodePublishResult result = latest.getOrDefault(
                    nodeId,
                    new NodePublishResult(nodeId, false, 0, "missing_result")
            );
            if (result.success() && result.currentGeneration() >= snapshot.generation()) {
                successCount++;
            }
            finalResults.add(result);
        }

        String finalStatus;
        if (successCount == nodeIds.size()) {
            finalStatus = "success";
        } else if (successCount > 0) {
            finalStatus = "partial_success";
        } else {
            finalStatus = "failed";
        }
        publishRepository.updatePublishStatus(snapshot.publishId(), finalStatus);

        return finalResults;
    }

    private Set<String> checkConvergence(
            String publishId,
            long generation,
            List<String> nodeIds,
            Map<String, NodePublishResult> latest
    ) {
        Set<String> pending = new LinkedHashSet<>();
        for (String nodeId : nodeIds) {
            NodePublishResult status = adminClient.status(nodeId);
            latest.put(nodeId, status);
            publishRepository.saveNodeResult(publishId, status);

            if (!status.success() || status.currentGeneration() < generation) {
                pending.add(nodeId);
            }
        }
        return pending;
    }

    private void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
