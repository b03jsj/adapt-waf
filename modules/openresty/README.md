# OpenResty 统一入口

该模块采用一个 Nginx 入口进程，拆分两个 `server` 块：

- `server:8080`：业务请求拦截链路（`access + log`）
- `server:18080`：内部管理接口（发布/状态/回退）

## 目录约定

- `conf/nginx.conf`：统一入口配置（包含两个 `server`）
- `conf/waf-config.json`：OpenResty 运行配置（拦截端 + 管理端）
- `lua/waf/interceptor/`：拦截端 Lua 代码
- `lua/waf/admin/`：管理端 Lua 代码

## 设计约束

- 管理端与拦截端代码分目录维护，但共享同一 OpenResty 进程。
- 请求热路径禁止阻塞 I/O，禁止 Lua 在请求路径直接写文件。
- 管理接口允许低频文件原子替换，不进入业务热路径。
- `rollback` 接口默认不执行本地回退，回退通过 Java 控制面执行“旧快照新代次 publish”。

## 当前已实现能力

- `access` 主链：黑名单快速匹配 -> 检测器 -> 豁免匹配 -> 策略聚合 -> 动作执行
- `hard_timeout_ms` 覆盖 `request_context` 构建到策略聚合全链路，超时统一 `fail-open`
- 检测器输入面：`URI + query + 小体积 body(json/form/text + multipart 文件名元数据)`
- `norm-v1` 规范化：URL decode、XSS entity decode、模型输入折叠
- `SGD` Lua 推断：读取 `manifest.json + weights.bin`（`float32 little-endian`）
- `libinjection` 接入策略：支持“强依赖”与“fallback 降级”配置
- `timeout_fail_open`：检测超时强制放行并记录高优先告警日志
- 结构化日志落盘：`waf-alert.ndjson`（必开）+ `waf-sample.ndjson`（采样）+ `waf-trace.ndjson`（默认关）
- 豁免热加载：按 `generation + sha256 + schema` 三重校验生效

## 配置方式

- 统一读取 `conf/waf-config.json`，不依赖环境变量。
- 拦截端配置在 `interceptor` 节点。
- 管理端配置在 `admin` 节点（含签名鉴权 `shared_secret`）。

## 验证脚本

- `../../scripts/verify_static_contracts.sh`
- `../../scripts/verify_pattern_key_contract.sh`
- `../../scripts/openresty_admin_publish_smoke.sh`
- `../../scripts/openresty_access_perf_smoke.sh`
