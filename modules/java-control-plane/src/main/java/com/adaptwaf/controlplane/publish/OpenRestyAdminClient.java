package com.adaptwaf.controlplane.publish;

import com.adaptwaf.controlplane.model.ExemptionCompiledSnapshot;
import com.adaptwaf.controlplane.model.NodePublishResult;

/**
 * OpenResty 管理接口客户端。
 */
public interface OpenRestyAdminClient {

    /**
     * 将整包豁免快照发布到指定节点。
     *
     * @param nodeId 节点标识
     * @param snapshot 编译快照
     * @return 节点发布结果
     */
    NodePublishResult publish(String nodeId, ExemptionCompiledSnapshot snapshot);

    /**
     * 查询节点当前生效状态。
     *
     * @param nodeId 节点标识
     * @return 节点状态
     */
    NodePublishResult status(String nodeId);
}
