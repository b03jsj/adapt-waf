package com.adaptwaf.controlplane.repository;

import com.adaptwaf.controlplane.model.NodePublishResult;
import com.adaptwaf.controlplane.model.PublishNodeResult;
import com.adaptwaf.controlplane.model.PublishRecord;
import java.util.List;

/**
 * 发布状态仓储接口。
 */
public interface PublishRepository {

    /**
     * 记录一次发布任务。
     *
     * @param publishId 发布任务标识
     * @param generation 发布代次
     * @param sha256 快照哈希
     * @param operator 操作人
     * @param reason 发布原因
     */
    void createPublish(String publishId, long generation, String sha256, String operator, String reason);

    /**
     * 记录单节点发布结果。
     *
     * @param publishId 发布任务标识
     * @param result 节点结果
     */
    void saveNodeResult(String publishId, NodePublishResult result);

    /**
     * 更新发布任务最终状态。
     *
     * @param publishId 发布任务标识
     * @param status 状态（success/partial_success/failed）
     */
    void updatePublishStatus(String publishId, String status);

    /**
     * 查询发布任务的节点结果。
     *
     * @param publishId 发布任务 ID
     * @return 节点结果列表
     */
    List<PublishNodeResult> listNodeResults(String publishId);

    /**
     * 查询发布历史。
     *
     * @param limit 限制条数
     * @param offset 偏移量
     * @return 发布记录
     */
    List<PublishRecord> listPublishes(int limit, int offset);

    /**
     * 按状态查询发布历史。
     *
     * @param status 状态，可为空
     * @param limit 限制条数
     * @param offset 偏移量
     * @return 发布记录
     */
    List<PublishRecord> listPublishes(String status, int limit, int offset);

    /**
     * 统计发布任务数量。
     *
     * @param status 状态，可为空
     * @return 总数
     */
    long countPublishes(String status);
}
