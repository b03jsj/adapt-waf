## OpenResty WAF Workspace

该仓库用于实现 OpenResty WAF 方案的工程骨架。

### 模块布局

- `modules/openresty/`: 统一 OpenResty 入口（两个 `server`：拦截端 + 管理端）
- `modules/java-control-plane/`: 日志采集、审核、发布编排、MySQL 持久化
- `modules/shared-spec/`: 各模块共享的 API/日志/Schema 契约
- `docs/`: 方案总览与详细实现文档

### 固定运行策略

- 主拦截在 `access` 阶段执行。
- `log` 阶段负责结构化日志与短期信誉黑名单更新（仅影响后续请求）。
- OpenResty 不直连数据库。
- Java 控制面负责页面审核、候选管理、快照发布与回滚编排。
- Java 控制面通过单一 `serve` 入口启动（API + ingest + auto-suggest）。
- OpenResty 与 Java 均采用配置文件驱动（不依赖环境变量作为主配置入口）。

### 迭代优先级

1. 完成 `modules/shared-spec/` 契约与代码实现对齐。
2. 在 `modules/openresty/` 接入 libinjection、规则引擎、SGD Lua 推断。
3. 在 `modules/java-control-plane/` 完成 ingest/review/publish 真实实现。
4. 联调验证发布链路：`compile -> publish -> apply -> status -> rollback`。

### 验证入口

- 联调与验收：`docs/openresty-waf-validation.md`
- 静态校验：`scripts/verify_static_contracts.sh`
- 一致性校验：`scripts/verify_pattern_key_contract.sh`
- 管理面 smoke：`scripts/openresty_admin_publish_smoke.sh`
- access 时延 smoke：`scripts/openresty_access_perf_smoke.sh`
