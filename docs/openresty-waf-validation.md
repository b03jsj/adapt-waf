# OpenResty WAF 联调与验证手册

本文档对应三类目标：

- 最小联调闭环
- 文档/代码/契约一致性验证
- 轻量性能 smoke

## 1. 规范入口

- 总览：`docs/openresty-waf-overview.md`
- 实现规范：`docs/openresty-waf-implementation.md`
- 共享契约：`modules/shared-spec/`
- OpenResty 配置：`modules/openresty/conf/waf-config.json`
- Java 配置：`modules/java-control-plane/conf/control-plane-config.json`

## 2. 最小联调前置

1. MySQL 已初始化 `modules/java-control-plane/sql/schema.sql`
2. OpenResty 节点可写：
   - `/var/log/nginx/`
   - `/opt/waf/policy/`
3. 业务回源已启动，或把 `modules/openresty/conf/nginx.conf` 中 `proxy_pass` 临时替换为固定 `return 200`
4. 两端配置文件已按本地环境修改：
   - OpenResty：`modules/openresty/conf/waf-config.json`
   - Java：`modules/java-control-plane/conf/control-plane-config.json`

## 3. 先跑静态契约检查

执行：

```bash
bash ./scripts/verify_static_contracts.sh
bash ./scripts/verify_pattern_key_contract.sh
```

通过标准：

- JSON 配置与 schema 语法通过
- OpenResty Lua 语法通过
- 主文档与 `shared-spec` 不再残留已废弃语义
- `pattern_key_v1` 在 Java 与 Lua 下输出一致

## 4. 最小联调闭环

### 4.1 启动 OpenResty

```bash
openresty -p modules/openresty -c conf/nginx.conf
```

检查：

```bash
curl -s http://127.0.0.1:18080/_waf/internal/healthz
curl -s http://127.0.0.1:18080/_waf/internal/exemptions/status
```

### 4.2 启动 Java 控制面

```bash
cd modules/java-control-plane
mvn -q -DskipTests package
java -cp target/classes com.adaptwaf.controlplane.Application --config conf/control-plane-config.json serve
```

若本地未安装 Maven，至少需要先生成 `target/classes` 再执行 `serve`。

检查：

```bash
curl -s http://127.0.0.1:28080/api/v1/review/healthz
curl -s http://127.0.0.1:28080/api/v1/review/summary
```

### 4.3 造一组 parser 命中流量

```bash
curl -s "http://127.0.0.1:8080/?q=' or 1=1 --" >/dev/null
```

验证：

- `waf-alert.ndjson` 产生告警事件
- Java ingest 将事件写入 MySQL
- `first_seen` 或 `candidate` 页面/API 可查询到对应模式

### 4.4 审核并发布豁免

1. 通过 Java API 审批候选
2. 触发 `publish`
3. 检查 OpenResty `status`：
   - `target_generation` 递增
   - `current_generation` 追平
   - `last_apply_status = ok`

### 4.5 验证回退

回退只走 Java 控制面：

```bash
POST /api/v1/review/rollback
```

通过标准：

- 新 `generation` 大于旧值
- `compiled_sha256` 可回到历史值
- OpenResty `/_waf/internal/exemptions/rollback` 仅作为占位接口，不承担历史快照管理

## 5. 可执行 smoke 脚本

### 5.1 OpenResty 管理面 publish/status

```bash
bash ./scripts/openresty_admin_publish_smoke.sh
```

脚本行为：

- 读取 `modules/openresty/conf/waf-config.json` 中的签名密钥
- 构造最小 `compiled.json` 快照
- 调用 `publish`
- 轮询 `status`，等待 worker 应用完成

### 5.2 access 时延 smoke

```bash
TARGET_URL=http://127.0.0.1:8080/ bash ./scripts/openresty_access_perf_smoke.sh
```

默认阈值：

- `p95 < 2ms`
- `p99 < 5ms`
- `max < 10ms`

说明：

- 这是顺序 smoke，不替代正式压测
- 正式压测仍应补 `wrk/k6` 等并覆盖 `shadow -> assist -> selective_enforce`

## 6. 验收清单

- `verify_static_contracts.sh` 通过
- `verify_pattern_key_contract.sh` 通过
- OpenResty `healthz/status` 正常
- Java `healthz/summary` 正常
- 日志可入 MySQL
- 候选可审批
- 发布后 OpenResty `generation` 收敛
- 回退通过 Java 完成且 `generation` 单调递增
- `openresty_admin_publish_smoke.sh` 通过
- `openresty_access_perf_smoke.sh` 在目标环境下通过

## 7. 当前边界

- 本手册提供的是“最小可执行验证资产”
- 不包含全量压测脚本、长稳 soak test、跨节点故障注入
- 若要作为上线门禁，仍需在 CI/CD 或预发环境追加：
  - MySQL 抖动场景
  - 黑名单容量/淘汰场景
  - SGD shadow 观察期指标回归
