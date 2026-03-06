package com.adaptwaf.controlplane.bootstrap;

import com.adaptwaf.controlplane.api.ControlPlaneApiServer;
import com.adaptwaf.controlplane.config.ControlPlaneConfig;
import com.adaptwaf.controlplane.ingest.FileTailIngestJob;
import com.adaptwaf.controlplane.ingest.NdjsonAlertIngestor;
import com.adaptwaf.controlplane.publish.HttpOpenRestyAdminClient;
import com.adaptwaf.controlplane.publish.OpenRestyAdminClient;
import com.adaptwaf.controlplane.publish.PublishCoordinator;
import com.adaptwaf.controlplane.repository.CandidateRepository;
import com.adaptwaf.controlplane.repository.PatternAggregateRepository;
import com.adaptwaf.controlplane.repository.jdbc.JdbcAlertEventRepository;
import com.adaptwaf.controlplane.repository.jdbc.JdbcBatchOperationRepository;
import com.adaptwaf.controlplane.repository.jdbc.JdbcCandidateRepository;
import com.adaptwaf.controlplane.repository.jdbc.JdbcExemptionRepository;
import com.adaptwaf.controlplane.repository.jdbc.JdbcIngestCheckpointRepository;
import com.adaptwaf.controlplane.repository.jdbc.JdbcPatternAggregateRepository;
import com.adaptwaf.controlplane.repository.jdbc.JdbcPatternStateRepository;
import com.adaptwaf.controlplane.repository.jdbc.JdbcPublishRepository;
import com.adaptwaf.controlplane.repository.jdbc.JdbcPublishSnapshotRepository;
import com.adaptwaf.controlplane.repository.jdbc.JdbcReviewAuditRepository;
import com.adaptwaf.controlplane.service.AutoSuggestJob;
import com.adaptwaf.controlplane.service.AutoSuggestService;
import com.adaptwaf.controlplane.service.BatchOperationService;
import com.adaptwaf.controlplane.service.ExemptionCompilerService;
import com.adaptwaf.controlplane.service.ExemptionPublishService;
import com.adaptwaf.controlplane.service.ReviewWorkflowService;
import com.adaptwaf.controlplane.service.SgdDatasetPrepareService;
import com.adaptwaf.controlplane.service.SgdReleaseGateService;
import com.adaptwaf.controlplane.util.SimpleDriverDataSource;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import javax.sql.DataSource;

/**
 * 控制面依赖装配器。
 */
public class ControlPlaneWiring {

    private final ControlPlaneConfig config;
    private final ObjectMapper objectMapper;
    private final DataSource dataSource;

    public ControlPlaneWiring(ControlPlaneConfig config) {
        this.config = config;
        this.objectMapper = new ObjectMapper();
        this.dataSource = new SimpleDriverDataSource(
                config.mysqlUrl(),
                config.mysqlUser(),
                config.mysqlPassword()
        );
    }

    /**
     * 构建日志采集任务。
     *
     * @return 采集任务
     */
    public FileTailIngestJob buildIngestJob() {
        NdjsonAlertIngestor ingestor = new NdjsonAlertIngestor(
                objectMapper,
                new JdbcAlertEventRepository(dataSource),
                new JdbcPatternStateRepository(dataSource)
        );
        return new FileTailIngestJob(
                config.sourceNode(),
                config.alertLogPath(),
                new JdbcIngestCheckpointRepository(dataSource),
                ingestor,
                config.ingestBatchSize()
        );
    }

    /**
     * 构建自动建议任务。
     *
     * @return 自动建议任务
     */
    public AutoSuggestJob buildAutoSuggestJob() {
        PatternAggregateRepository aggregateRepository = new JdbcPatternAggregateRepository(dataSource);
        CandidateRepository candidateRepository = new JdbcCandidateRepository(dataSource, objectMapper);
        AutoSuggestService autoSuggestService = new AutoSuggestService(
                config.autoSuggestMinHits(),
                config.autoSuggestMin2xxRatio(),
                config.autoSuggestMinUniqueIp(),
                config.autoSuggestMaxSingleIpRatio(),
                config.autoSuggestMinIpEntropyBits(),
                config.autoSuggestMinActiveDays(),
                config.autoSuggestMaxPeakDayRatio()
        );
        return new AutoSuggestJob(aggregateRepository, candidateRepository, autoSuggestService);
    }

    /**
     * 构建豁免发布服务。
     *
     * @return 发布服务
     */
    public ExemptionPublishService buildExemptionPublishService() {
        return buildExemptionPublishServiceWithSnapshot();
    }

    /**
     * 构建豁免发布服务（含快照回退支持）。
     *
     * @return 发布服务
     */
    public ExemptionPublishService buildExemptionPublishServiceWithSnapshot() {
        ExemptionCompilerService compilerService = buildExemptionCompilerService();
        PublishCoordinator coordinator = new PublishCoordinator(
                buildAdminClient(),
                new JdbcPublishRepository(dataSource),
                config.publishMaxAttempts(),
                config.publishRetryIntervalMillis()
        );
        return new ExemptionPublishService(
                compilerService,
                coordinator,
                new JdbcPublishSnapshotRepository(dataSource),
                config.exemptionsAuthoringSource()
        );
    }

    /**
     * 构建豁免编译服务。
     *
     * @return 编译服务
     */
    public ExemptionCompilerService buildExemptionCompilerService() {
        var patternStateRepository = new JdbcPatternStateRepository(dataSource);
        return new ExemptionCompilerService(
                new JdbcExemptionRepository(dataSource, objectMapper),
                patternStateRepository,
                objectMapper
        );
    }

    /**
     * 构建审核工作流服务。
     *
     * @return 审核服务
     */
    public ReviewWorkflowService buildReviewWorkflowService() {
        return new ReviewWorkflowService(
                new JdbcAlertEventRepository(dataSource),
                new JdbcCandidateRepository(dataSource, objectMapper),
                new JdbcExemptionRepository(dataSource, objectMapper),
                new JdbcPatternStateRepository(dataSource),
                new JdbcReviewAuditRepository(dataSource),
                objectMapper
        );
    }

    /**
     * 构建管理 API 服务器。
     *
     * @return API 服务器
     */
    public ControlPlaneApiServer buildApiServer() {
        return new ControlPlaneApiServer(
                config,
                objectMapper,
                buildReviewWorkflowService(),
                buildBatchOperationService(),
                buildExemptionPublishService(),
                new JdbcPublishRepository(dataSource)
        );
    }

    /**
     * 构建批量审核任务服务。
     *
     * @return 批量任务服务
     */
    public BatchOperationService buildBatchOperationService() {
        return new BatchOperationService(
                buildReviewWorkflowService(),
                new JdbcBatchOperationRepository(dataSource),
                config.reviewBatchWorkerThreads()
        );
    }

    /**
     * 构建 SGD 样本准备服务。
     *
     * @return 样本准备服务
     */
    public SgdDatasetPrepareService buildSgdDatasetPrepareService() {
        return new SgdDatasetPrepareService(dataSource, objectMapper, config);
    }

    /**
     * 构建 SGD 发布门禁服务。
     *
     * @return 门禁服务
     */
    public SgdReleaseGateService buildSgdReleaseGateService() {
        return new SgdReleaseGateService(objectMapper, config);
    }

    /**
     * 计算默认自动建议窗口起始时间。
     *
     * @return 起始时间
     */
    public Instant autoSuggestFromTime() {
        Duration duration = config.autoSuggestWindow();
        return Instant.now().minus(duration);
    }

    private OpenRestyAdminClient buildAdminClient() {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();

        Map<String, String> nodeMap = new HashMap<>();
        for (String node : config.publishNodes()) {
            if (node.contains("=")) {
                String[] parts = node.split("=", 2);
                String nodeId = parts[0].trim();
                String baseUrl = parts[1].trim();
                if (!nodeId.isBlank() && !baseUrl.isBlank()) {
                    nodeMap.put(nodeId, baseUrl);
                }
                continue;
            }
            nodeMap.put(node, node);
        }

        return new HttpOpenRestyAdminClient(
                client,
                objectMapper,
                nodeMap,
                config.openrestySharedSecret()
        );
    }
}
