package com.adaptwaf.controlplane;

import com.adaptwaf.controlplane.api.ControlPlaneApiServer;
import com.adaptwaf.controlplane.bootstrap.ControlPlaneWiring;
import com.adaptwaf.controlplane.config.ControlPlaneConfig;
import com.adaptwaf.controlplane.ingest.FileTailIngestJob;
import com.adaptwaf.controlplane.model.NodePublishResult;
import com.adaptwaf.controlplane.service.AutoSuggestJob;
import com.adaptwaf.controlplane.service.ExemptionPublishService;
import com.adaptwaf.controlplane.service.SgdDatasetPrepareService;
import com.adaptwaf.controlplane.service.SgdReleaseGateService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 控制面启动入口。
 */
public final class Application {

    private static final Path DEFAULT_CONFIG_PATH = Path.of("conf/control-plane-config.json");

    private Application() {
    }

    /**
     * 启动入口。
     *
     * @param args 启动参数
     */
    public static void main(String[] args) throws Exception {
        ParsedArgs parsedArgs = parseArgs(args);
        ControlPlaneConfig config = ControlPlaneConfig.fromFile(parsedArgs.configPath());
        ControlPlaneWiring wiring = new ControlPlaneWiring(config);

        String[] commandArgs = parsedArgs.commandArgs();
        String command = (commandArgs.length == 0) ? "serve" : commandArgs[0];
        switch (command) {
            case "serve", "serve-api" -> runServe(wiring, config);
            case "task" -> runTask(wiring, config, Arrays.copyOfRange(commandArgs, 1, commandArgs.length));
            default -> {
                // 兼容旧命令写法：未显式写 task 时，自动按 task 子命令执行。
                runTask(wiring, config, commandArgs);
            }
        }
    }

    /**
     * 运行统一控制面主进程。
     * 说明：该入口负责启动 API，并按配置调度 ingest/auto-suggest 后台循环。
     */
    private static void runServe(ControlPlaneWiring wiring, ControlPlaneConfig config) throws Exception {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2, runnable -> {
            Thread thread = new Thread(runnable);
            thread.setName("waf-control-plane-scheduler");
            thread.setDaemon(false);
            return thread;
        });

        Runtime.getRuntime().addShutdownHook(new Thread(() -> scheduler.shutdownNow(), "waf-control-plane-shutdown"));

        if (config.runtimeEnableIngestLoop()) {
            long intervalMs = Math.max(1000L, config.ingestLoopInterval().toMillis());
            FileTailIngestJob ingestJob = wiring.buildIngestJob();
            scheduler.scheduleWithFixedDelay(() -> {
                try {
                    ingestJob.runOnce();
                } catch (Exception e) {
                    System.err.println("ingest_loop_error:" + safeMessage(e));
                }
            }, 0, intervalMs, TimeUnit.MILLISECONDS);
            System.out.println("ingest_loop_enabled interval_ms=" + intervalMs);
        }

        if (config.runtimeEnableAutoSuggestLoop()) {
            long intervalMs = Math.max(5000L, config.autoSuggestLoopInterval().toMillis());
            AutoSuggestJob autoSuggestJob = wiring.buildAutoSuggestJob();
            scheduler.scheduleWithFixedDelay(() -> {
                try {
                    autoSuggestJob.run(wiring.autoSuggestFromTime(), Instant.now());
                } catch (Exception e) {
                    System.err.println("auto_suggest_loop_error:" + safeMessage(e));
                }
            }, 0, intervalMs, TimeUnit.MILLISECONDS);
            System.out.println("auto_suggest_loop_enabled interval_ms=" + intervalMs);
        }

        if (config.runtimeEnableApiServer()) {
            ControlPlaneApiServer apiServer = wiring.buildApiServer();
            apiServer.startAndBlock();
            return;
        }

        if (!config.runtimeEnableIngestLoop() && !config.runtimeEnableAutoSuggestLoop()) {
            throw new IllegalArgumentException("runtime_no_component_enabled");
        }

        System.out.println("api_server_disabled, keep_loops_running=true");
        new CountDownLatch(1).await();
    }

    /**
     * 执行一次性任务子命令。
     */
    private static void runTask(ControlPlaneWiring wiring, ControlPlaneConfig config, String[] taskArgs) throws Exception {
        if (taskArgs == null || taskArgs.length == 0) {
            printHelp();
            return;
        }

        String task = taskArgs[0];
        switch (task) {
            case "ingest-once" -> {
                wiring.buildIngestJob().runOnce();
                System.out.println("ingest_once_done");
            }
            case "auto-suggest-once" -> {
                AutoSuggestJob job = wiring.buildAutoSuggestJob();
                job.run(wiring.autoSuggestFromTime(), Instant.now());
                System.out.println("auto_suggest_once_done");
            }
            case "prepare-sgd-dataset" -> {
                Path outputDir = null;
                if (taskArgs.length >= 2 && taskArgs[1] != null && !taskArgs[1].isBlank()) {
                    outputDir = Path.of(taskArgs[1]);
                }

                SgdDatasetPrepareService prepareService = wiring.buildSgdDatasetPrepareService();
                var result = prepareService.prepare(outputDir);
                System.out.println("sgd_dataset_prepare_done");
                System.out.println("output_dir=" + result.outputDir());
                System.out.println("total_samples=" + result.totalSamples());
                System.out.println("source_counts=" + result.sourceCounts());
                System.out.println("attack_type_counts=" + result.attackTypeCounts());
            }
            case "sgd-show-state" -> {
                if (taskArgs.length < 2) {
                    throw new IllegalArgumentException("usage: task sgd-show-state <manifest_path>");
                }
                SgdReleaseGateService service = wiring.buildSgdReleaseGateService();
                var summary = service.show(Path.of(taskArgs[1]));
                System.out.println("attack_type=" + summary.attackType());
                System.out.println("model_version=" + summary.modelVersion());
                System.out.println("model_state=" + summary.modelState());
                System.out.println("normalization_profile=" + summary.normalizationProfile());
            }
            case "sgd-set-state" -> {
                if (taskArgs.length < 3) {
                    throw new IllegalArgumentException("usage: task sgd-set-state <manifest_path> <candidate|shadow_observe|stable>");
                }
                SgdReleaseGateService service = wiring.buildSgdReleaseGateService();
                var summary = service.setModelState(Path.of(taskArgs[1]), taskArgs[2]);
                System.out.println("sgd_set_state_done");
                System.out.println("model_version=" + summary.modelVersion());
                System.out.println("model_state=" + summary.modelState());
            }
            case "sgd-gate-offline" -> {
                if (taskArgs.length < 3) {
                    throw new IllegalArgumentException("usage: task sgd-gate-offline <manifest_path> <offline_metrics_report.json>");
                }
                SgdReleaseGateService service = wiring.buildSgdReleaseGateService();
                var result = service.promoteToShadowObserve(Path.of(taskArgs[1]), Path.of(taskArgs[2]));
                System.out.println("sgd_gate_offline_passed=" + result.passed());
                System.out.println("from_state=" + result.fromState());
                System.out.println("to_state=" + result.toState());
                System.out.println("failed_checks=" + result.failedChecks());
            }
            case "sgd-gate-shadow" -> {
                if (taskArgs.length < 3) {
                    throw new IllegalArgumentException("usage: task sgd-gate-shadow <manifest_path> <shadow_metrics_report.json>");
                }
                SgdReleaseGateService service = wiring.buildSgdReleaseGateService();
                var result = service.promoteToStable(Path.of(taskArgs[1]), Path.of(taskArgs[2]));
                System.out.println("sgd_gate_shadow_passed=" + result.passed());
                System.out.println("from_state=" + result.fromState());
                System.out.println("to_state=" + result.toState());
                System.out.println("failed_checks=" + result.failedChecks());
            }
            case "compile-exemptions-source" -> {
                if (taskArgs.length < 5) {
                    throw new IllegalArgumentException(
                            "usage: task compile-exemptions-source <generation> <publish_id> <source_yaml_or_json> <output_compiled_json>"
                    );
                }
                long generation = Long.parseLong(taskArgs[1]);
                String publishId = taskArgs[2];
                Path sourcePath = Path.of(taskArgs[3]);
                Path outputPath = Path.of(taskArgs[4]);
                var compiler = wiring.buildExemptionCompilerService();
                var compiled = compiler.compileFromAuthoringFile(generation, publishId, sourcePath);
                if (outputPath.getParent() != null) {
                    Files.createDirectories(outputPath.getParent());
                }
                Files.write(outputPath, compiled.content());
                System.out.println("compile_exemptions_source_done");
                System.out.println("output=" + outputPath);
                System.out.println("sha256=" + compiled.sha256());
                System.out.println("size=" + compiled.content().length);
            }
            case "publish-exemptions" -> {
                if (taskArgs.length < 4) {
                    throw new IllegalArgumentException("usage: task publish-exemptions <generation> <operator> <reason>");
                }
                long generation = Long.parseLong(taskArgs[1]);
                String operator = taskArgs[2];
                String reason = String.join(" ", Arrays.copyOfRange(taskArgs, 3, taskArgs.length));
                ExemptionPublishService publishService = wiring.buildExemptionPublishService();
                List<String> nodes = config.publishNodes();
                List<NodePublishResult> results = publishService.publish(generation, nodes, operator, reason);
                long successCount = results.stream().filter(NodePublishResult::success).count();
                System.out.println("publish_done success=" + successCount + "/" + results.size());
            }
            case "rollback-exemptions" -> {
                if (taskArgs.length < 5) {
                    throw new IllegalArgumentException(
                            "usage: task rollback-exemptions <rollback_from_generation> <new_generation> <operator> <reason>"
                    );
                }
                long rollbackFromGeneration = Long.parseLong(taskArgs[1]);
                long newGeneration = Long.parseLong(taskArgs[2]);
                String operator = taskArgs[3];
                String reason = String.join(" ", Arrays.copyOfRange(taskArgs, 4, taskArgs.length));
                ExemptionPublishService publishService = wiring.buildExemptionPublishService();
                List<String> nodes = config.publishNodes();
                List<NodePublishResult> results = publishService.rollback(
                        rollbackFromGeneration,
                        newGeneration,
                        nodes,
                        operator,
                        reason
                );
                long successCount = results.stream().filter(NodePublishResult::success).count();
                System.out.println("rollback_done success=" + successCount + "/" + results.size());
            }
            case "help", "--help", "-h" -> printHelp();
            default -> printHelp();
        }
    }

    /**
     * 打印命令帮助信息。
     */
    private static void printHelp() {
        System.out.println("usage:");
        System.out.println("  Application [--config <path>] serve");
        System.out.println("  Application [--config <path>] task <subcommand> ...");
        System.out.println("default config: " + DEFAULT_CONFIG_PATH);
        System.out.println();
        System.out.println("runtime:");
        System.out.println("  serve");
        System.out.println("    单一主入口，按配置启动 API + ingest loop + auto-suggest loop");
        System.out.println();
        System.out.println("task subcommands:");
        System.out.println("  ingest-once");
        System.out.println("  auto-suggest-once");
        System.out.println("  prepare-sgd-dataset [output_dir]");
        System.out.println("  sgd-show-state <manifest_path>");
        System.out.println("  sgd-set-state <manifest_path> <candidate|shadow_observe|stable>");
        System.out.println("  sgd-gate-offline <manifest_path> <offline_metrics_report.json>");
        System.out.println("  sgd-gate-shadow <manifest_path> <shadow_metrics_report.json>");
        System.out.println("  compile-exemptions-source <generation> <publish_id> <source_yaml_or_json> <output_compiled_json>");
        System.out.println("  publish-exemptions <generation> <operator> <reason>");
        System.out.println("  rollback-exemptions <rollback_from_generation> <new_generation> <operator> <reason>");
    }

    private static String safeMessage(Exception e) {
        if (e == null || e.getMessage() == null || e.getMessage().isBlank()) {
            return "unknown";
        }
        return e.getMessage();
    }

    /**
     * 解析命令行参数，提取配置文件路径与实际命令参数。
     */
    private static ParsedArgs parseArgs(String[] args) {
        if (args == null || args.length == 0) {
            return new ParsedArgs(DEFAULT_CONFIG_PATH, new String[0]);
        }

        if ("--config".equals(args[0])) {
            if (args.length < 2 || args[1] == null || args[1].isBlank()) {
                throw new IllegalArgumentException("usage: --config <path>");
            }
            Path configPath = Path.of(args[1]);
            String[] commandArgs = Arrays.copyOfRange(args, 2, args.length);
            return new ParsedArgs(configPath, commandArgs);
        }

        return new ParsedArgs(DEFAULT_CONFIG_PATH, args);
    }

    /**
     * 启动参数解析结果。
     *
     * @param configPath 配置文件路径
     * @param commandArgs 命令参数
     */
    private record ParsedArgs(Path configPath, String[] commandArgs) {
    }
}
