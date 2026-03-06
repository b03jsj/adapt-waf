package com.adaptwaf.controlplane.repository;

import com.adaptwaf.controlplane.model.ExemptionCompiledSnapshot;

/**
 * 发布快照仓储接口。
 */
public interface PublishSnapshotRepository {

    /**
     * 保存一次发布快照。
     *
     * @param snapshot 发布快照
     */
    void saveSnapshot(ExemptionCompiledSnapshot snapshot);

    /**
     * 按 generation 读取历史发布快照。
     *
     * @param generation 历史代次
     * @return 快照；不存在时返回 null
     */
    ExemptionCompiledSnapshot findByGeneration(long generation);
}
