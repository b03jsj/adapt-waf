# Java 控制面

该模块负责：

- 读取 OpenResty 结构化日志并入库 MySQL
- 计算 `pattern_key_v1`、`first_seen_pattern`、`ip_entropy`
- 提供审核与发布编排能力
- 调用 OpenResty 管理接口推送豁免快照

## 目录说明

- `src/main/java/`: Java 代码骨架
- `sql/schema.sql`: MySQL 表结构初稿
- `sql/migrations/`: 旧库增量迁移脚本（`ALTER TABLE`）

## 开发约束

- 数据库仅使用 MySQL 8.0+
- 所有对外接口方法必须有中文注释
- 复用优先，避免重复实现 `pattern_key_v1` 构造与签名逻辑

## 当前骨架范围

- `ingest/`：NDJSON 入库编排
- `service/`：`pattern_key_v1`、`ip_entropy`、候选判定与编译服务
- `publish/`：OpenResty 发布编排接口
- `repository/`：MySQL 仓储接口定义与 JDBC 实现
- `repository/jdbc/`：基于 `DataSource` 的仓储落地实现

## 已落地链路

- 日志采集：`FileTailIngestJob -> NdjsonAlertIngestor -> Jdbc*Repository`
- 自动候选：`AutoSuggestJob -> JdbcPatternAggregateRepository -> JdbcCandidateRepository`
- 豁免发布：`ExemptionPublishService -> ExemptionCompilerService -> PublishCoordinator(重试+收敛) -> HttpOpenRestyAdminClient`
- 回退重发：`rollback-exemptions` 按历史 generation 读取快照并以新 generation 重发
- 管理 API：`serve` 启动审核后端接口（first-seen/candidate/audit/publish/rollback）

## 配置文件

- 默认读取：`conf/control-plane-config.json`
- 可通过启动参数覆盖：`--config <path>`
- 配置节点：
  - `runtime`：是否启用 API / ingest loop / auto-suggest loop
  - `mysql`：数据库连接
  - `ingest`：日志采集路径、批次、轮询间隔
  - `auto_suggest`：候选阈值（含 `min_active_days`、`max_peak_day_ratio`）
  - `sgd_dataset` / `sgd_gate`：样本与模型门禁参数
  - `review_api`：管理接口监听与 token
  - `publish`：OpenResty 节点、签名密钥、重试参数
  - `exemptions.authoring_source`：可选，发布时优先从文件编译

## 审核 API 路径

- `GET /api/v1/review/first-seen`
- `GET /api/v1/review/summary`
- 支持筛选参数：
  - `route_key/detector/method/content_type/surface/alert_level/from_time/to_time`
  - `status/reason_like/pattern_key_like/updated_from/updated_to`
  - `format=json|csv`（first-seen/candidates 可导出 CSV）
- `GET /api/v1/review/candidates?status=auto_suggested`
- `POST /api/v1/review/candidates/{id}/approve`
- `POST /api/v1/review/candidates/{id}/reject`
- `POST /api/v1/review/candidates/batch/approve?format=json|csv`
- `POST /api/v1/review/candidates/batch/reject?format=json|csv`
- `POST /api/v1/review/candidates/batch/approve-async`
- `POST /api/v1/review/candidates/batch/reject-async`
- `GET /api/v1/review/candidates/batch`
- `GET /api/v1/review/candidates/batch/{operation_id}`
- `GET /api/v1/review/candidates/batch/{operation_id}/items?format=json|csv`
- `GET /api/v1/review/audit`
- `GET /api/v1/review/publish`
- `POST /api/v1/review/publish`
- `POST /api/v1/review/rollback`
- `GET /api/v1/review/publish/{publish_id}/nodes`
- `GET /api/v1/review/healthz`

> 当配置 `review_api.token` 后，调用方需携带 `X-Waf-Api-Token` 请求头。

## 启动命令（收敛后）

- 主入口（推荐）：
  - `java ... com.adaptwaf.controlplane.Application [--config conf/control-plane-config.json] serve`
  - 启动单一控制面进程，按配置开启 API + ingest loop + auto-suggest loop
- 运维任务入口：
  - `java ... com.adaptwaf.controlplane.Application [--config conf/control-plane-config.json] task ingest-once`
  - `java ... com.adaptwaf.controlplane.Application [--config conf/control-plane-config.json] task auto-suggest-once`
  - `java ... com.adaptwaf.controlplane.Application [--config conf/control-plane-config.json] task prepare-sgd-dataset [output_dir]`
  - `java ... com.adaptwaf.controlplane.Application [--config conf/control-plane-config.json] task sgd-show-state <manifest_path>`
  - `java ... com.adaptwaf.controlplane.Application [--config conf/control-plane-config.json] task sgd-set-state <manifest_path> <candidate|shadow_observe|stable>`
  - `java ... com.adaptwaf.controlplane.Application [--config conf/control-plane-config.json] task sgd-gate-offline <manifest_path> <offline_metrics_report.json>`
  - `java ... com.adaptwaf.controlplane.Application [--config conf/control-plane-config.json] task sgd-gate-shadow <manifest_path> <shadow_metrics_report.json>`
  - `java ... com.adaptwaf.controlplane.Application [--config conf/control-plane-config.json] task compile-exemptions-source <generation> <publish_id> <source_yaml_or_json> <output_compiled_json>`
  - `java ... com.adaptwaf.controlplane.Application [--config conf/control-plane-config.json] task publish-exemptions <generation> <operator> <reason>`
  - `java ... com.adaptwaf.controlplane.Application [--config conf/control-plane-config.json] task rollback-exemptions <rollback_from_generation> <new_generation> <operator> <reason>`

## 验证入口

- 联调与验收：`../../docs/openresty-waf-validation.md`
- 静态校验：`../../scripts/verify_static_contracts.sh`
- 一致性校验：`../../scripts/verify_pattern_key_contract.sh`

## 增量迁移（已有 MySQL 库）

若不是新建库，先执行：

```sql
SOURCE modules/java-control-plane/sql/migrations/20260305_incremental_upgrade.sql;
```

该脚本会补齐：

- `waf_alert_event.pattern_key_text/pattern_key_hash`
- `waf_pattern_state` 的 hash 主键与兼容列
- `waf_exemption_candidate.pattern_key_text/pattern_key_hash`

## Auto Suggest 反投毒护栏

自动候选仅统计以下事件：

- `detector in (libinjection_sqli, libinjection_xss)`
- `policy_decision_basis like parser_hit_%`
- `exemption_applied = 0`
- `pattern_state` 为 `unknown`（已确认攻击/误报不再参与候选）

默认门槛（可调）：

- `hits >= 200`
- `2xx_ratio >= 99.5%`
- `unique_ip >= 20`
- `single_ip_ratio < 20%`
- `ip_entropy >= 2.5 bits`
- `active_days >= 2`
- `peak_day_ratio <= 70%`

## SGD 样本一键准备（已落地）

> 目标：不需要手工拼接攻击语料，直接产出可训练 NDJSON。

执行：

```bash
java ... com.adaptwaf.controlplane.Application task prepare-sgd-dataset
```

输出目录默认：

- `sgd_dataset.output_dir`（默认 `./out/sgd-dataset`）
- 每次运行会创建 UTC 时间戳子目录

输出文件：

- `sqli.all.ndjson` / `sqli.train.ndjson` / `sqli.val.ndjson`
- `xss.all.ndjson` / `xss.train.ndjson` / `xss.val.ndjson`
- `summary.json`

样本来源（自动合并）：

1. MySQL：
   - 正样本：`attack_confirmed`
   - 负样本：`benign_confirmed`
   - hard negative：`exemption_applied=1` 且 `parser_hit_exempted_*`
2. 内置离线攻击语料：
   - `src/main/resources/sgd-seeds/sqli-payloads.txt`
   - `src/main/resources/sgd-seeds/xss-payloads.txt`
3. 可选外部 payload 文件（每行一条）：
   - `sgd_dataset.extra_sqli_payload_path`
   - `sgd_dataset.extra_xss_payload_path`

### 外部 payload 文件准备示例（可直接用）

你可以先用工具导出 payload 文本文件，再喂给准备命令。

示例目录：

```bash
mkdir -p /opt/waf/offline-payloads
```

手工补充 SQLi：

```bash
cat > /opt/waf/offline-payloads/sqli-extra.txt <<'EOF'
' or 1=1 --
union select 1,2,3
and sleep(5)
EOF
```

手工补充 XSS：

```bash
cat > /opt/waf/offline-payloads/xss-extra.txt <<'EOF'
<script>alert(1)</script>
<img src=x onerror=alert(1)>
javascript:alert(1)
EOF
```

在 `conf/control-plane-config.json` 中设置：

```bash
"sgd_dataset": {
  "extra_sqli_payload_path": "/opt/waf/offline-payloads/sqli-extra.txt",
  "extra_xss_payload_path": "/opt/waf/offline-payloads/xss-extra.txt"
}
```

执行准备：

```bash
java ... com.adaptwaf.controlplane.Application task prepare-sgd-dataset
```
