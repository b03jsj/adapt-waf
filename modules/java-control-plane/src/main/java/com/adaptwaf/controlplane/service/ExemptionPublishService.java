package com.adaptwaf.controlplane.service;

import com.adaptwaf.controlplane.model.ExemptionCompiledSnapshot;
import com.adaptwaf.controlplane.model.NodePublishResult;
import com.adaptwaf.controlplane.publish.PublishCoordinator;
import com.adaptwaf.controlplane.repository.PublishSnapshotRepository;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

/**
 * 豁免发布服务。
 */
public class ExemptionPublishService {

    private final ExemptionCompilerService exemptionCompilerService;
    private final PublishCoordinator publishCoordinator;
    private final PublishSnapshotRepository publishSnapshotRepository;
    private final Path authoringSource;

    public ExemptionPublishService(
            ExemptionCompilerService exemptionCompilerService,
            PublishCoordinator publishCoordinator,
            PublishSnapshotRepository publishSnapshotRepository,
            Path authoringSource
    ) {
        this.exemptionCompilerService = exemptionCompilerService;
        this.publishCoordinator = publishCoordinator;
        this.publishSnapshotRepository = publishSnapshotRepository;
        this.authoringSource = authoringSource;
    }

    /**
     * 编译并发布整包豁免快照。
     *
     * @param generation 新代次（必须单调递增）
     * @param nodeIds 目标节点列表
     * @param operator 操作人
     * @param reason 发布原因
     * @return 节点发布结果
     * @throws Exception 编译失败异常
     */
    public List<NodePublishResult> publish(
            long generation,
            List<String> nodeIds,
            String operator,
            String reason
    ) throws Exception {
        return publish(generation, nodeIds, operator, reason, authoringSource);
    }

    /**
     * 编译并发布整包豁免快照（可指定 source 覆盖默认来源）。
     *
     * @param generation 新代次（必须单调递增）
     * @param nodeIds 目标节点列表
     * @param operator 操作人
     * @param reason 发布原因
     * @param sourcePath 可选来源文件（YAML/JSON）
     * @return 节点发布结果
     * @throws Exception 编译失败异常
     */
    public List<NodePublishResult> publish(
            long generation,
            List<String> nodeIds,
            String operator,
            String reason,
            Path sourcePath
    ) throws Exception {
        if (nodeIds == null || nodeIds.isEmpty()) {
            throw new IllegalArgumentException("publish_nodes_empty");
        }

        String publishId = "pub_" + UUID.randomUUID().toString().replace("-", "");
        ExemptionCompilerService.CompiledResult compiledResult;
        if (sourcePath != null && Files.exists(sourcePath)) {
            compiledResult = exemptionCompilerService.compileFromAuthoringFile(generation, publishId, sourcePath);
        } else {
            compiledResult = exemptionCompilerService.compile(generation, publishId);
        }

        ExemptionCompiledSnapshot snapshot = new ExemptionCompiledSnapshot(
                generation,
                publishId,
                compiledResult.sha256(),
                compiledResult.content()
        );

        List<NodePublishResult> results = publishCoordinator.publishAll(snapshot, nodeIds, operator, reason);
        publishSnapshotRepository.saveSnapshot(snapshot);
        return results;
    }

    /**
     * 使用历史稳定快照执行回退重发（旧内容新代次）。
     *
     * @param rollbackFromGeneration 历史代次
     * @param newGeneration 新代次
     * @param nodeIds 目标节点列表
     * @param operator 操作人
     * @param reason 回退原因
     * @return 节点发布结果
     */
    public List<NodePublishResult> rollback(
            long rollbackFromGeneration,
            long newGeneration,
            List<String> nodeIds,
            String operator,
            String reason
    ) {
        if (nodeIds == null || nodeIds.isEmpty()) {
            throw new IllegalArgumentException("publish_nodes_empty");
        }

        ExemptionCompiledSnapshot history = publishSnapshotRepository.findByGeneration(rollbackFromGeneration);
        if (history == null) {
            throw new IllegalArgumentException("rollback_source_generation_not_found:" + rollbackFromGeneration);
        }

        String publishId = "pub_" + UUID.randomUUID().toString().replace("-", "");
        ExemptionCompiledSnapshot republished = new ExemptionCompiledSnapshot(
                newGeneration,
                publishId,
                history.sha256(),
                history.content()
        );

        List<NodePublishResult> results = publishCoordinator.publishAll(republished, nodeIds, operator, reason);
        publishSnapshotRepository.saveSnapshot(republished);
        return results;
    }
}
