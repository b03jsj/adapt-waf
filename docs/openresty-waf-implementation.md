# OpenResty WAF 详细实现说明

> 返回总览： [OpenResty WAF 总览（流程骨架版）](./openresty-waf-overview.md)

本文件是实现规范源。  
阈值、字段、状态机、日志结构、测试门禁以本文件为准。

联调与 smoke 执行步骤见：
[OpenResty WAF 联调与验证手册](./openresty-waf-validation.md)。

<a id="impl-scope"></a>
## 0. 摘要与范围

第一版固定范围：

- 防护类型：`SQLi + XSS`
- 运行时：`OpenResty + Lua`（`libinjection` + 轻量规则 + `SGD` 辅助评分）
- 训练：`Java` 夜间批处理
- 模式：`shadow | assist | selective_enforce`

第一版固定原则：

- 不使用大型外部负向规则库
- 不依赖业务接口契约作为上线前提
- 不允许 `model-only block`
- 检测超时固定 `fail-open`
- 运营最小人工：自动候选 + first-seen 复核 + 指标门禁自动晋级
- 运营与审核链路只使用 `MySQL 8.0+`（不引入 ES/ClickHouse）
- 日志展示、候选审核、豁免发布全部在 Java 层完成
- OpenResty 不连数据库，只负责日志落盘与豁免快照接收

---

<a id="impl-pipeline"></a>
## 1. 检测链实现细则

[返回总览](./openresty-waf-overview.md#3-运行时主流程骨架10步)

### 1.1 热路径顺序（固定）

1. 访问前置检查（`access` 黑名单快速匹配）
2. 请求信息选择
3. 统一规范化（`norm-v1`）
4. 字段切分
5. 高置信检测（`libinjection_sqli/xss`）
6. 精确豁免匹配（`signature_exact -> detector_field`）
7. 轻量规则与弱启发式
8. `SGD` 辅助评分
9. 策略聚合
10. 动作执行（当前请求）
11. 结构化日志输出（`log` 阶段可更新信誉黑名单）

### 1.2 组件职责

- `libinjection_sqli` / `libinjection_xss`
  - 提供高置信 parser 信号
- `exemption_matcher`
  - 处理误报放行（精确优先、放宽需审批）
- `reputation_blacklist`
  - 在 `access` 做 O(1) 快速命中拦截
  - 在 `log` 基于事件更新短 TTL 信誉黑名单
- `rule_engine`
  - 小规则集（规模受控）
- `heuristic_signals`
  - 长度/字符集/编码/密度等弱信号
- `sgd_sqli` / `sgd_xss`
  - 只辅助评分，不单独阻断

### 1.3 `policy_decision_basis` 固定取值

- `parser_hit_shadow`
- `parser_hit_assist_first_seen`
- `parser_hit_assist_known_benign`
- `parser_hit_assist_known_attack`
- `parser_hit_block`
- `parser_hit_exempted_exact`
- `parser_hit_exempted_detector_field`
- `blacklist_hit`
- `detector_unavailable_fail_open`
- `weak_combo_only`
- `model_only`
- `timeout_fail_open`
- `none`

<a id="impl-modes"></a>
### 1.4 模式语义

#### `shadow`

- 执行完整检测链
- `enforced_action=allow`
- 输出完整日志/样本
- 进入模式聚类统计，生成 `auto_suggested` 候选

#### `assist`

- 执行完整检测链
- 默认不阻断新模式
- 人工只处理 first-seen 模式
- 历史模式自动沿用记忆库策略

#### `selective_enforce`

- 未豁免高置信命中允许真实阻断
- 弱规则 + 高模型分默认不直接阻断

### 1.5 模式记忆库（Pattern Memory）

统一键定义：`pattern_key_v1`

- 固定构成：
  - `method | route_key | content_type | surface | field_selector | detector | signature_token`
- 字段规则：
  - `method`：大写（如 `POST`）
  - `route_key`：运行时路由归一化值
  - `content_type`：主类型归一化（如 `application/json`）
  - `field_selector`：
    - `surface=json` 使用 `json_path`
    - 其他 surface 使用 `field_name`
    - 缺失时使用 `-`
  - `signature_token`：
    - parser 命中使用 fingerprint
    - 无 fingerprint 使用 `-`
- 一致性要求：
  - OpenResty 与 Java 必须使用同一构造规范（同输入必同 key）

状态：

- `unknown`
- `benign_confirmed`
- `attack_confirmed`

统计：

- `first_seen`
- `last_seen`
- `hit_count`
- `last_decision`

行为：

- `unknown`：仅首次入人工复核
- `benign_confirmed`：自动按历史放行/豁免
- `attack_confirmed`：`selective_enforce` 下进入阻断候选

### 1.6 硬拦截入口（默认）

入口 A：黑名单快速命中（`access`）：

1. `reputation_blacklist_hit = true`
2. 条目未过期

入口 B：高置信检测命中（`access`）：

1. `libinjection` 命中
2. 未命中豁免
3. 模式为 `selective_enforce`
4. 不在高误报字段保护范围
5. 未触发 `timeout_fail_open`

---

<a id="impl-normalization"></a>
## 2. 规范化契约 `norm-v1`

[返回总览](./openresty-waf-overview.md#3-运行时主流程骨架10步)

### 2.1 总则

- `normalization_profile` 是训练/推断一致性契约，不是注释字段
- 第一版固定：`active_profile = norm-v1`
- Java 训练、Lua 推断、规则引擎、离线回放必须共享同一 profile

### 2.2 URL decode（按 surface）

- `query = 2`
- `form = 2`
- `multipart_filename = 2`
- `json = 0`
- `text/plain = 0`
- `header = 0`
- `multipart_text = 0`

规则：

- 最大 `2` 次
- 每轮无变化可提前停止
- `%2527` 必须展开到 `'`

### 2.3 HTML entity decode

- XSS 视图：最多 2 次
- SQLi 视图：0 次

### 2.4 Unicode 与文本变换

- `unicode_normalization = none`
- 仅 UTF-8 合法性校验
- 模型与弱规则输入做：
  - ASCII 小写
  - ASCII 空白折叠
- 不得删除关键符号（引号、注释、比较符、括号、标签分隔符等）

### 2.5 模型输入长度

- `model_feature_max_bytes = 2048`
- 超出截断并标记 `model_input_truncated=true`

### 2.6 固定视图

每字段固定生成：

- `raw_value`
- `normalized_sqli_value`
- `normalized_xss_value`
- `model_sqli_input`
- `model_xss_input`

---

<a id="impl-exemption-hot-reload"></a>
## 3. 豁免热更新实现

[返回总览](./openresty-waf-overview.md#8-发布与回退骨架)

### 3.1 匹配范围与策略

`match_scope`：

- `signature_exact`（默认）
- `detector_field`（显式放宽）

`detector_field` 约束：

- 仅允许 `libinjection_sqli/xss`
- 至少 2 个误报事件依据
- 需 `scope_relaxation_approved=true`
- 必须设置 `expires_at`，默认 TTL 30 天

### 3.2 运行时工件

- 规则主源：Java 审核通过后的 `waf_exemption_rule`
- 可选文件源：`authoring_source`（YAML/JSON）
- 运行时加载：`exemptions.compiled.json`

### 3.3 编译与发布链

固定路径（Java 编排）：

1. Java 审核页确认候选后更新 `waf_exemption_rule` 并记录 `waf_review_audit`
2. Java 发布服务执行编译：
   - 默认从已审批规则仓储编译
   - 若传入 `authoring_source`，则用 YAML/JSON 文件覆盖默认来源
3. Java 校验：
   - 文件源存在性（若启用）
   - JSON / YAML 子集语法
   - schema_version
   - 重复 key
   - scope 合法性
4. Java 计算 `sha256/size`，生成 `publish_id + generation`
5. Java 并发调用每个 OpenResty 节点：
   - `POST /_waf/internal/exemptions/publish`
6. 节点校验通过后原子 rename：
   - `*.tmp -> exemptions.compiled.json`
7. worker 热加载生效（无需 reload）

失败时：

- 节点不覆盖旧 `compiled.json`
- 节点不推进 generation
- 旧快照继续服务
- Java 记录失败节点并持续重试（允许部分成功）

### 3.4 加载时机与热更新

- `init_worker_by_lua*`：
  - 加载本地只读快照
  - 启动定时器

热更新：

- 管理接口写入 `target_generation/target_sha256/target_size`
- 所有 worker 每 1s 检查 `target_generation`
- generation 变化后重建本地索引并原子替换引用
- 不再依赖 worker 主动轮询磁盘文件变更

### 3.5 索引与冲突

索引：

- `exact_index`：
  - `method|route_key|content_type|surface|field_name|json_path|detector|signature`
- `detector_field_index`：
  - `method|route_key|content_type|surface|field_name|json_path|detector`

匹配顺序：

1. `signature_exact`
2. `detector_field`
3. no match

冲突：

- 同 key 重复条目 -> 加载失败

### 3.6 热更新 SLO

- 新豁免从发布到全 worker 生效目标：`<= 10s`

### 3.7 OpenResty 管理接口（豁免发布）

固定接口：

- `POST /_waf/internal/exemptions/publish`
- `GET /_waf/internal/exemptions/status`
- `POST /_waf/internal/exemptions/rollback`（可选）

`publish` 请求体最小字段：

- `publish_id`
- `generation`
- `compiled_sha256`
- `compiled_size`
- `compiled_content_base64`（或 gzip 版本）
- `operator`
- `reason`
- `created_at`

节点校验：

- 管理面鉴权默认是“内网 + 请求签名 + 防重放”
- `mTLS` 在当前实现中为可选增强，不是默认必开项
- `generation` 必须单调递增
- `sha256/size` 一致
- JSON/schema/重复 key 通过

回退语义：

- OpenResty `/_waf/internal/exemptions/rollback` 当前返回 `501`
- 真正的回退由 Java 控制面完成：读取历史快照并以新 `generation` 重新调用 `publish`
- `rollback` 不会让 `generation` 递减
- 回退是“历史稳定快照作为新内容重新发布”，`generation` 继续递增
- 回退后 `compiled_sha256` 可回到历史值

`status` 返回最小字段：

- `node_id`
- `current_generation`
- `target_generation`
- `last_apply_status`
- `last_error`
- `last_apply_ts`

---

<a id="impl-pattern-memory"></a>
## 4. 模式记忆库与自动候选算法

[返回总览](./openresty-waf-overview.md#6-运营自动化骨架)

### 4.1 Shadow 自动候选（不逐条 review）

聚类键：

- `pattern_key_v1`

窗口：

- `N = 7 days`

触发条件（全满足）：

1. `hits >= 200`
2. `2xx_ratio >= 99.5%`
3. 来源分散：
   - `unique_ip >= 20`
   - `ip_entropy >= 2.5`
   - `single_ip_ratio < 0.2`
4. 扫描器占比低于阈值（默认 5%）
5. 历史无 `attack_confirmed` 冲突

输出：

- `candidate_status = auto_suggested`
- `candidate_reason = high_freq_benign_pattern`

默认：

- `auto_apply = false`

#### 4.1.1 `ip_entropy` 定义

- 输入集合：某 `pattern_key_v1` 在窗口 `N days` 内命中事件集合
- 统计维度：来源 IP（默认 `client_ip`，已按可信代理链归一化）
- Shannon entropy（单位 bits）：
  - `p_i = count(ip_i) / total_hits`
  - `ip_entropy = -Σ p_i * log2(p_i)`
- 解释量：
  - `effective_ip_count = 2 ^ ip_entropy`
  - `ip_entropy = 2.5` 约等于 `effective_ip_count ≈ 5.66`（约 6 个均匀独立 IP）
- 关系约束：
  - `unique_ip`、`single_ip_ratio`、`ip_entropy` 基于同一 IP 分布计算
- 预留配置（可选）：
  - `entropy_ip_granularity: ip | ipv4_c24 | ipv6_c64`（默认 `ip`）

### 4.2 First-seen 复核

- 归属：`first_seen_pattern` 只在 Java ingest 侧判定，OpenResty 热路径不判定
- OpenResty：
  - 必须输出 `pattern_key_v1`
  - `first_seen_pattern` 可为空或不输出（由 Java 补全）
- Java ingest：
  - 入库时对 `waf_pattern_state(pattern_key_hash)` 做原子 upsert
  - 首次成功插入该 `pattern_key_hash` 的事件标记 `first_seen_pattern=true`
  - 后续同 key 事件标记 `false`
- 人工队列：
  - 仅 Java 侧 `first_seen_pattern=true` 的 `high` 事件入人工队列
- 判定基准：
  - 以“首次成功入库”为准，不以事件时间最早值为准（避免乱序歧义）

### 4.3 候选生命周期

- `auto_suggested -> approved/rejected -> expired`

### 4.4 反投毒护栏

- 单 IP 高频不得触发自动候选
- 扫描器特征高占比不得触发自动候选
- 历史攻击冲突键不得触发自动候选

---

<a id="impl-policy-aggregation"></a>
## 5. 告警分级、策略聚合、timeout fail-open

[返回总览](./openresty-waf-overview.md#5-硬拦截边界)

### 5.1 威胁分类

- `confirmed_attack`
- `suspected_attack`
- `sample_only`
- `none`

### 5.2 告警等级

- `critical`
- `high`
- `low`
- `none`

### 5.3 关键动作矩阵（摘要）

- 黑名单命中：
  - 所有模式：`block`（`policy_decision_basis=blacklist_hit`）
- 未豁免 parser 命中：
  - `shadow`：log
  - `assist`：high/critical（first-seen 才人工）
  - `selective_enforce`：block
- parser 命中且豁免：
  - allow + 审计日志
- weak+high sgd：
  - 默认 high 告警，不阻断
- model-only：
  - sample/log，不阻断

### 5.4 `access + log` 双阶段策略（固定）

- `access`：
  - 先做黑名单快速匹配（`shared_dict` O(1)）
  - 未命中则执行主检测链
  - 只对当前请求做阻断决策
- `log`：
  - 基于最终信号更新信誉分
  - 达到阈值后写入黑名单（短 TTL）
  - 不回溯改变当前请求结果，仅影响后续请求
- 默认键：
  - `blacklist_key = ip + ua_hash`（预留 `session_id` 扩展位）
- 风险控制：
  - 避免“纯 IP”长期封禁（NAT 误伤）
  - 黑名单条目必须有 TTL 与最大容量

### 5.5 timeout fail-open

- `hard_timeout_ms` 是检测链请求级硬预算
- 任一检查点超时：
  - `decision_candidate=allow`
  - `enforced_action=allow`
  - `policy_decision_basis=timeout_fail_open`
  - `alert_level=high`
  - `budget_exhausted=true`

必须记录：

- `timeout_stage`
- `elapsed_ms`
- `hard_timeout_ms`
- `detector_stage_reached`

---

<a id="impl-sgd"></a>
## 6. SGD 训练/加载/发布门禁（Lua FFI 在线推断）

[返回总览](./openresty-waf-overview.md#7-sgd-生命周期骨架)

### 6.1 定位

- 仅辅助评分
- 不单独阻断
- 运行时后端：`lua_ffi`

### 6.2 工件格式

- `manifest.json`
- `weights.bin`（`float32 le` flat array）

必须字段：

- `format/attack_type/hash_dim/ngram_min/ngram_max/dtype/bias`
- `weights_file/weights_sha256`
- `model_version/parent_version/trained_at`
- `normalization_profile`

### 6.3 加载与校验

`init_worker_by_lua*`：

1. 读 manifest
2. 校验结构
3. 校验 `manifest.normalization_profile == active_profile`
4. 读 weights
5. 校验 sha256
6. LuaJIT FFI 建连续内存视图

失败：

- 模型不生效
- `sgd_model_state=disabled`
- 写告警

### 6.4 状态机与门禁

状态：

- `cold_start`
- `candidate`
- `shadow_observe`
- `stable`
- `disabled`

发布状态机：

- `candidate -> shadow_observe -> stable`

门禁：

- 离线门禁通过才进 `shadow_observe`
- 影子门禁通过才自动晋级 `stable`
- 异常时保持旧 stable 并告警

### 6.5 样本与离线门槛

- `positive >= 1000`
- `negative >= 5000`
- `hard_negative >= 1000`
- `precision_at_assist_threshold >= 0.95`
- `clean_fpr <= 0.001`
- `hard_negative_fpr <= 0.01`

### 6.6 影子门禁（默认）

- `shadow_observe_hours >= 72`
- `predicted_high` 抽检误报率不超阈值
- 相比上个 stable 无显著回归
- timeout/资源指标未恶化

---

<a id="impl-config"></a>
## 7. 配置接口（规范源）

[返回总览](./openresty-waf-overview.md#9-性能与资源目标)

### 7.1 主配置（摘要+关键字段）

说明：

- 当前代码实际读取的是 JSON 配置文件：
  - `modules/openresty/conf/waf-config.json`
  - `modules/java-control-plane/conf/control-plane-config.json`
- 下方 YAML 片段是“逻辑结构映射”，用于说明字段分层，不要求与落地文件格式完全同形。

```yaml
waf:
  mode: shadow | assist | selective_enforce
  parser:
    libinjection_sql: true
    libinjection_xss: true
  normalization:
    active_profile: norm-v1
    norm_v1:
      url_decode_max_passes: 2
      url_decode_surfaces:
        query: 2
        form: 2
        multipart_filename: 2
        json: 0
        text_plain: 0
        header: 0
        multipart_text: 0
      html_entity_decode_for_xss: true
      html_entity_decode_max_passes: 2
      html_entity_decode_for_sqli: false
      unicode_normalization: none
      ascii_lowercase_for_model: true
      ascii_whitespace_fold_for_model: true
      model_feature_max_bytes: 2048
    log_value_max_bytes: 512
  exemptions:
    enabled: true
    runtime_source: "/opt/waf/policy/exemptions.compiled.json"
    hot_reload: true
    publish_mode: push_snapshot
    allow_partial_publish: true
    worker_apply_interval_seconds: 1
    shared_dict: "waf_control"
    allow_detector_scope_exemption: true
    detector_scope_default_ttl_days: 30
    require_exact_scope: true
  management_api:
    enabled: true
    bind: "0.0.0.0:18080"
    internal_only: true
    mTLS_required: false
    request_signature_required: true
    anti_replay_window_seconds: 300
  operations:
    review_mode: pattern_first_seen
    shadow_auto_suggest:
      enabled: true
      window_days: 7
      min_hits: 200
      min_2xx_ratio: 0.995
      min_unique_ip: 20
      min_ip_entropy: 2.5
      entropy_ip_granularity: ip
      max_single_ip_ratio: 0.2
      scanner_ratio_threshold: 0.05
      auto_apply: false
    high_queue:
      only_first_seen: true
    pattern_memory:
      enabled: true
      states: [unknown, benign_confirmed, attack_confirmed]
    sgd_release:
      auto_promote: true
      shadow_observe_hours: 72
      promote_on_metrics: true
      require_manual_on_anomaly: true
  reputation_blacklist:
    enabled: true
    dict_name: "waf_blacklist"
    key_mode: ip_ua
    key_delimiter: "|"
    ttl_seconds: 600
    max_entries: 200000
    score_threshold: 3
    allow_session_dimension: true
    session_field_name: "x-session-id"
  capture:
    query_max_args: 64
    query_max_bytes: 8192
    body_parse_max_bytes: 131072
    body_parse_hard_max_bytes: 1048576
    allowed_content_types:
      - application/json
      - application/x-www-form-urlencoded
      - text/plain
    allow_temp_file_readback: true
    inspect_multipart_filename: true
    multipart_filename_max_bytes: 512
    inspect_multipart_file_content: false
  model:
    scorer_backend: lua_ffi
    scorer_backend_fallback: c_mmap
    allow_model_only_block: false
    min_positive_samples: 1000
    min_negative_samples: 5000
    min_hard_negative_samples: 1000
    min_precision_at_assist_threshold: 0.95
    max_clean_false_positive_rate: 0.001
    max_hard_negative_false_positive_rate: 0.01
    sqli_manifest_path: "/opt/waf/models/sqli/current.manifest.json"
    xss_manifest_path: "/opt/waf/models/xss/current.manifest.json"
    sqli_weights_path: "/opt/waf/models/sqli/current.weights.bin"
    xss_weights_path: "/opt/waf/models/xss/current.weights.bin"
  logging:
    alert_log_enabled: true
    trace_log_enabled: false
    sample_log_enabled: true
    sample_rate: 0.02
    file_format: ndjson
    nginx_buffer: "512k"
    nginx_flush_seconds: 5
    rotate:
      max_size_mb: 512
      interval: hourly
    local_retention_hours: 72
    disk_watermark:
      disable_sample_percent: 80
      high_critical_only_percent: 90
      minimal_fields_percent: 95
  limits:
    target_p95_ms: 2
    target_p99_ms: 5
    hard_timeout_ms: 10
    timeout_policy: fail_open
    timeout_alert_level: high
    request_extra_mem_soft_bytes: 524288
    request_extra_mem_large_bytes: 2097152
    request_extra_mem_hard_bytes: 33554432
    worker_extra_rss_target_bytes: 25165824
```

说明：

- OpenResty 配置中不包含任何数据库连接字段。
- `operations.*` 的审核策略由 Java 平台执行，OpenResty 只消费发布结果（`compiled + generation`）。

### 7.2 版本对象

- `base_model_version`
- `policy_version`
- `ruleset_version`
- `exemptions_generation`

规则：

- 热更新豁免只推进 `exemptions_generation`
- 周期归档策略才推进 `policy_version`

---

<a id="impl-java-mysql"></a>
## 8. Java 运营链路（仅 MySQL）

[返回总览](./openresty-waf-overview.md#6-运营自动化骨架)

### 8.1 职责边界

- OpenResty：
  - 结构化日志落盘（`NDJSON`）
  - 执行检测与阻断
  - 接收 Java 下发的 `compiled + generation`
- Java：
  - 日志读取入库
  - 候选聚类与审核页面
  - 豁免编译与发布编排
  - 发布重试与状态收敛
- 数据库：
  - 仅 `MySQL 8.0+`
  - 不引入 ES/ClickHouse

### 8.2 MySQL 数据模型（规范源）

概念类型：

- `pattern_key_v1`
- `ip_entropy_bits`
- `effective_ip_count`

`waf_alert_event`（事件明细）：

- 用途：检索、聚合、候选生成
- 关键字段：
  - `event_id`（唯一）
  - `event_time`
  - `route_key/method/content_type/surface/field_name/json_path`
  - `detector/detector_signature`
  - `threat_classification/alert_level/final_action`
  - `status_code/client_ip/user_agent_hash`
  - `pattern_key_text/pattern_key_hash/first_seen_pattern`
  - `exemption_applied/exemption_id/exemption_match_scope`
  - `policy_decision_basis/normalization_profile`
  - `payload_json`（JSON，大字段）
- 字段语义：
  - `pattern_key_text`：按 `pattern_key_v1` 构造的可读键
  - `pattern_key_hash`：`pattern_key_text` 的稳定哈希（索引键）
  - `first_seen_pattern`：由 Java ingest 在入库时判定（OpenResty 不实时判定）
- 关键索引：
  - `uniq_event_id(event_id)`
  - `idx_time(event_time)`
  - `idx_review(alert_level, first_seen_pattern, event_time)`
  - `idx_pattern(pattern_key_hash, event_time)`
  - `idx_route_field(route_key, field_name, event_time)`

`waf_pattern_state`（模式状态）：

- 主键：`pattern_key_hash`
- 字段：`pattern_state/first_seen/last_seen/hit_count/last_decision`
- 备注：保留 `pattern_key_text` 便于审计与页面展示

`waf_exemption_candidate`（候选）：

- 字段：`candidate_id/pattern_key_hash/candidate_status/candidate_reason/metrics_snapshot/created_at/updated_at`

`waf_exemption_rule`（已批准豁免）：

- 存审批后规则，作为 `exemptions.yaml` 导出源

`waf_exemption_publish`（发布批次）：

- 字段：`publish_id/generation/sha256/operator/reason/status/created_at`

`waf_exemption_publish_node_result`（节点结果）：

- 唯一键：`(publish_id, node_id)`
- 字段：`node_status/current_generation/last_error/updated_at`

`waf_review_audit`（审核审计，append-only）：

- 字段：`audit_id/operator/action/target_type/target_id/before_json/after_json/reason/ticket_id/created_at`

`waf_ingest_checkpoint`（采集位点）：

- 唯一键：`(source_node, file_path)`
- 字段：`inode/offset/updated_at`

### 8.3 日志入库链路（Java ingest）

固定策略：

- 读取方式：按文件 offset 增量读取
- 批次：每 `5s` 或 `2000` 条提交一次（先到先写）
- 幂等：`event_id` 唯一 + `insert ignore`（或等价空更新）
- 背压：DB 写入超时时自动降批次并告警
- 可见性目标：新事件 `<= 60s` 在审核页面可见
- first-seen 判定：
  - 先按 `pattern_key_v1` 计算 `pattern_key_text` 与 `pattern_key_hash`
  - 对 `waf_pattern_state(pattern_key_hash)` 执行原子 upsert
  - 首次成功写入状态表时，当前事件写 `first_seen_pattern=true`
  - 后续事件写 `first_seen_pattern=false`
- 乱序/重试语义：
  - 判定基准固定为“首次成功入库”
  - 不因迟到日志改变既有 first-seen 结果

### 8.4 审核页面与操作路径

固定页面：

1. `first-seen` 队列页
2. `auto_suggested` 候选页（支持批量确认）
3. 发布状态页（按节点查看 generation）
4. 审计检索页（按人/时间/动作）

固定流程：

1. 人工在 Java 页面审批候选（单人审批）
2. Java 更新 `waf_exemption_rule` 并写 `waf_review_audit`
3. Java 编译 `exemptions.compiled.json`
4. Java 推送到各 OpenResty 节点
5. Java 轮询节点状态并更新发布记录

### 8.5 发布编排与失败语义

固定语义：

- 发布粒度：整包快照 + `generation`
- 拓扑：Java 主动推送每节点
- 失败策略：允许部分成功；失败节点持续重试
- 成功节点立即生效，失败节点保持旧代次

### 8.6 容量与保留策略

固定策略：

- 引擎：InnoDB
- 分区：`waf_alert_event` 按日 RANGE 分区
- 保留：30 天（按分区删除）
- 禁止大批量 `DELETE`
- 大字段 `payload_json` 仅详情页按需读取

---

<a id="impl-logs-metrics"></a>
## 9. 日志结构与指标告警

[返回总览](./openresty-waf-overview.md#6-运营自动化骨架)

### 9.1 运行时日志关键字段

- 基础：
  - `mode/decision_candidate/enforced_action/final_action`
- 检测：
  - `detector/detector_signature/plugin_signals`
- 豁免：
  - `exemption_applied/exemption_id/exemption_match_scope/exemption_match_key`
- 信誉黑名单：
  - `blacklist_key/blacklist_hit/blacklist_ttl_left/reputation_score/reputation_action`
- 记忆与候选：
  - `pattern_key/pattern_state/first_seen_pattern`
  - `candidate_status/candidate_reason`
- 模型：
  - `sgd_backend/sgd_model_state/sgd_score_raw/sgd_score_used/sgd_decision_weight/model_version`
- 规范化：
  - `normalization_profile/raw_value/normalized_*`
- 超时：
  - `timeout_stage/hard_timeout_ms/detector_stage_reached/budget_exhausted/elapsed_ms`
- 版本：
  - `base_model_version/policy_version/exemptions_generation`

语义约束：

- `pattern_key`：由 OpenResty 按 `pattern_key_v1` 构造并输出
- `first_seen_pattern`：由 Java ingest 入库时判定并落库，不在 OpenResty 热路径实时计算

### 9.2 日志分流与落盘规范

- `alert_log`：默认开
- `trace_log`：默认关
- `sample_log`：按采样率与配额
- OpenResty 仅允许 Nginx 缓冲日志写盘，禁止 Lua 请求路径直接写文件
- 推荐参数：
  - `buffer=512k`
  - `flush=5s`
  - `open_log_file_cache=on`
- 滚动策略：按小时或 `512MB`
- 本地保留：24-72h（供 Java 追平与补采）
- Java ingest 仅从日志文件读取并写入 `MySQL`，OpenResty 不直接写库
- 磁盘水位降级：
  - `disk > 80%`：关闭 `sample_log`
  - `disk > 90%`：仅保留 `high/critical`
  - `disk > 95%`：最小字段日志 + 高优告警

### 9.3 指标（最小集）

- `waf_exemptions_active_generation`
- `waf_exemptions_reload_success_total`
- `waf_exemptions_reload_failure_total`
- `waf_exemptions_match_total`
- `waf_exemptions_detector_scope_match_total`
- `waf_timeout_fail_open_total`
- `waf_timeout_fail_open_by_stage_total`
- `waf_timeout_fail_open_by_route_total`
- `waf_model_profile_mismatch_total`
- `waf_pattern_first_seen_total`
- `waf_pattern_auto_suggested_total`
- `waf_pattern_auto_suggest_approved_total`
- `waf_sgd_auto_promote_success_total`
- `waf_sgd_auto_promote_blocked_total`
- `waf_ingest_lag_seconds`
- `waf_publish_partial_success_total`
- `waf_publish_node_retry_total`
- `waf_blacklist_hit_total`
- `waf_blacklist_insert_total`
- `waf_blacklist_evict_total`

### 9.4 运维告警（最小集）

- 豁免热更新连续失败
- worker generation 落后超过 30s
- timeout_fail_open 比例异常
- normalization_profile mismatch
- detector_field 豁免数量异常增长
- first_seen 模式数量异常飙升
- auto_suggested 候选通过率异常下降
- SGD 自动晋级连续失败

---

<a id="impl-test-acceptance"></a>
## 10. 测试矩阵与验收门槛

[返回总览](./openresty-waf-overview.md#9-性能与资源目标)

### 10.1 功能测试

- SQLi/XSS 典型与变体 payload
- parser 命中在三模式下动作正确
- 豁免命中后放行且审计完整
- timeout 触发后 `fail_open`
- `multipart.filename` 全链路覆盖
- `publish/status` 接口请求与响应字段完整可用
- `access` 黑名单命中可直接拦截
- `log` 阶段更新黑名单仅影响后续请求

### 10.2 误报与运营测试

- first-seen 仅首次入队
- 历史 benign/attack 自动处理
- auto_suggest 条件正确触发/抑制
- 单 IP 高频、扫描器高占比不触发 auto_suggest
- `ip_entropy` 按 Shannon entropy（bits）计算，均匀 6 IP 分布约 `2.58`
- `ip_entropy` 与 `unique_ip/single_ip_ratio` 使用同一分布样本
- Java 审核页审批后可落库并产出可发布豁免
- 发布批次可看到节点级状态与失败原因

### 10.3 一致性测试

- Java/Lua 在 `norm-v1` 下特征一致
- manifest 与 runtime profile 不一致时模型禁用
- 模型权重 checksum 失败时不生效
- OpenResty 与 Java 对同请求构造的 `pattern_key_v1` 完全一致
- `application/json` 与 `application/x-www-form-urlencoded` 不得合并为同一 `pattern_key_v1`
- `field_selector/signature_token` 缺失占位规则一致（`-`）

当前最小可执行资产：

- `scripts/verify_pattern_key_contract.sh`

### 10.4 性能测试

- `amd64`、`arm64`
- `p95/p99` 检查
- 请求额外内存检查
- `lua_ffi` scorer 单字段基准
- 热更新传播 `<=10s`
- Java ingest 在目标负载下满足 `<=60s` 可见性
- MySQL 分区删除不影响在线查询 SLA
- 黑名单快速匹配对 `access` 链路增量 `p99` 在预算内

当前最小可执行资产：

- `scripts/openresty_access_perf_smoke.sh`

### 10.5 可靠性测试

- 节点部分失败时，成功节点不回退，失败节点可重试追平
- Java 重启后按 checkpoint 继续采集，无重复/漏采
- MySQL 短时抖动时 ingest 背压生效，不阻塞 OpenResty
- first-seen 判定对重试/重复日志保持稳定（不重复 first-seen）
- 乱序日志不会触发同一 `pattern_key_v1` 多次 first-seen
- 黑名单容量到上限时淘汰策略生效且不阻塞请求

当前最小可执行资产：

- `scripts/openresty_admin_publish_smoke.sh`

### 10.6 安全测试

- 未授权调用发布接口必须拒绝
- 非法 `sha256/schema` 的快照发布必须拒绝
- 过期 `timestamp` 或重复 `nonce` 请求必须拒绝
- 审计记录必须可追溯到 `operator/publish_id`
- rollback 发布后 `generation` 仍递增，`compiled_sha256` 与历史稳定快照一致

<a id="impl-scope-limits"></a>
### 10.7 安全边界与非目标

- 不扫描上传文件内容
- 无 `Content-Length` body 不深度解析
- 大包不做全量检测
- 不承诺覆盖所有上下文型/二阶攻击
- 发布接口仅管理面可访问，默认启用请求签名与防重放；`mTLS` 作为可选增强开启

---

<a id="impl-runbook"></a>
## 11. 运行手册（热更新、回退、异常处置）

[返回总览](./openresty-waf-overview.md#8-发布与回退骨架)

当前实现默认运行配置：

- OpenResty：`modules/openresty/conf/waf-config.json`
- Java：`modules/java-control-plane/conf/control-plane-config.json`
- 联调步骤与 smoke 命令：见 [OpenResty WAF 联调与验证手册](./openresty-waf-validation.md)

### 11.1 日常误报处理（热更新通道）

1. 在 Java 候选页批量确认 `auto_suggested` 或人工确认误报
2. Java 更新 `waf_exemption_rule` 并记录 `waf_review_audit`
3. Java 发布服务编译运行时快照：
   - 默认从已审批规则仓储编译
   - 如传入 `authoring_source`，则用文件源覆盖
4. Java 生成 `publish_id + generation` 并推送各节点 `publish` 接口
5. 节点原子落盘 `compiled.json`，worker 应用新 generation
6. Java 查询 `status` 收敛节点状态，失败节点持续重试
7. 抽样验证命中行为

### 11.2 模型发布（正式通道）

1. 夜间训练产出 `candidate`
2. 自动离线门禁
3. `shadow_observe` 观察
4. 自动影子门禁
5. 通过后自动晋级 `stable`

### 11.3 回退

- 豁免回退：
  - Java 选择历史稳定快照重新发布为新 `generation`
  - 校验所有节点 generation 收敛
  - OpenResty 本地 `rollback` 接口默认返回 `501`，不承担历史版本管理
  - 说明：回退不是 `generation` 递减，而是历史稳定快照作为新内容重发，`generation` 继续单调递增
  - 回退后现象：`generation` 变大，但 `compiled_sha256` 可回到历史值
- 正式发布回退：
  - 回退 `base_model_version/policy_version/ruleset_version`
  - `nginx reload`

### 11.4 常见异常处理

- 豁免热更新失败：
  - 节点保持旧快照
  - Java 查看节点 `last_error` 并重试发布
- 发布部分失败：
  - 标记批次 `partial_success`
  - 仅重试失败节点，不影响已成功节点
- 黑名单误封突增：
  - 检查 `blacklist_key` 维度是否过粗（如仅 IP）
  - 调低 `score_threshold` 触发权重或缩短 `ttl_seconds`
  - 必要时临时清空黑名单并保留审计
- timeout_fail_open 突增：
  - 检查热点阶段
  - 缩减检测预算或降级低优先插件
- SGD 自动晋级连续失败：
  - 停止晋级
  - 保持旧 stable
  - 排查数据分布漂移与误报变化

---

<a id="impl-dev-sequence"></a>
## 12. 开发实施顺序与工程组织

[返回总览](./openresty-waf-overview.md#8-发布与回退骨架)

### 12.1 目录拆分（固定）

OpenResty 统一采用一个入口进程，在同一份 `nginx.conf` 内加载两个 `server` 块：

- `modules/openresty/`
  - `conf/nginx.conf`
    - `server:8080` 业务拦截链路（`access/log`）
    - `server:18080` 管理接口（`publish/status/rollback`）
  - `lua/waf/interceptor/`
    - 仅放检测链、黑名单匹配、策略执行代码
  - `lua/waf/admin/`
    - 仅放管理接口与快照生效逻辑
- `modules/java-control-plane/`
  - 仅放 ingest、审核页面、编译发布编排、MySQL 持久化
- `modules/shared-spec/`
  - 放 OpenAPI、日志 schema、`pattern_key_v1` 构造规范

### 12.2 开发顺序（固定）

1. 固化契约：
   - `publish/status/rollback` 接口 schema
   - `NDJSON` 日志 schema
   - `pattern_key_v1` 构造函数规范
2. OpenResty 统一入口与拦截端：
   - 搭建单入口 `nginx.conf` 与双 `server` 块
   - `access` 黑名单快速匹配
   - 高置信检测链与阻断
   - `log` 信誉更新（只影响后续请求）
3. OpenResty 管理端：
   - `publish/status/rollback`
   - 快照校验、原子落盘、generation 生效
4. Java ingest 与 MySQL：
   - 文件 checkpoint、幂等入库
   - `first_seen_pattern` 判定与模式状态更新
5. Java 审核与发布编排：
   - `first-seen` 与 `auto_suggested` 页面
   - 编译、推送、节点状态收敛、失败重试
6. 端到端联调：
   - 黑名单命中链路
   - parser 阻断链路
   - rollback 新代次语义
7. 压测与灰度：
   - `access` 时延预算
   - 黑名单容量与淘汰行为
   - `shadow -> assist -> selective_enforce`

### 12.3 代码组织规范（固定）

- 接口方法必须有注释（请求字段、返回字段、错误语义、幂等性）。
- 业务方法拆分到单独文件，避免超大文件。
- 复用优先：公共逻辑沉淀到 `shared-spec` 或公共工具模块，禁止复制实现。
- 关键常量统一管理（键名、状态名、TTL、阈值）。

### 12.4 OpenResty 开发最佳实践（必须遵守）

- `access`/`log` 阶段禁止阻塞 I/O（不读写外部数据库、不做磁盘随机读）。
- 请求路径禁止 `io.open` 写日志，必须使用 Nginx 缓冲日志机制。
- 黑名单查询必须是 `shared_dict` O(1) 访问，且配置容量上限与 TTL。
- 管理接口写快照必须 `tmp + rename` 原子替换。
- 正则必须受控使用，启用 JIT 与缓存策略。
- 大对象分配与 JSON 解析避免放在高频热路径中重复创建。
- 定时任务与共享状态更新必须可观测（指标 + 错误日志）。

### 12.5 复用清单（建议）

- `pattern_key_v1` 构造函数：OpenResty 与 Java 共用同一规范实现。
- `generation` 与发布状态模型：管理接口、Java 发布器、页面统一复用。
- 日志字段常量：拦截端与 ingest 端复用，避免字段名漂移。
- 错误码与告警码：管理接口与 Java 编排统一编码。

---

## 附录 A：策略 YAML 示例（完整）

```yaml
rules:
  - id: xss_proto_001
    type: string
    target: field_value
    match: "javascript:"
    case_insensitive: true
    action: score
    score_tag: xss

  - id: sqli_comment_001
    type: regex
    target: field_value
    pattern: "/\\*.*?\\*/"
    options: "jo"
    action: score
    score_tag: sqli

exemptions:
  - id: exm_20260304_001
    enabled: true
    match_scope: signature_exact
    detector: libinjection_sqli
    signature: "sqli_fingerprint_xxx"
    method: POST
    route_key: /api/search
    content_type: application/json
    surface: json
    field_name: keyword
    json_path: "$.keyword"
    action: allow_log
    reason: "confirmed_false_positive"
    owner: secops
    source_event_ids:
      - evt_123456
    created_at: "2026-03-04T12:00:00Z"
    expires_at: null

  - id: exm_20260304_101
    enabled: true
    match_scope: detector_field
    detector: libinjection_sqli
    method: POST
    route_key: /api/search
    content_type: application/json
    surface: json
    field_name: keyword
    json_path: "$.keyword"
    action: allow_log
    reason: "repeated_false_positive"
    owner: secops
    source_event_ids:
      - evt_123456
      - evt_123789
    scope_relaxation_approved: true
    scope_relaxation_reason: "same field repeated false positives across multiple fingerprints"
    created_at: "2026-03-04T12:00:00Z"
    expires_at: "2026-04-03T12:00:00Z"
```

## 附录 B：测试场景清单（完整）

- 请求采集与解析：
  - 小 JSON/form 正常解析
  - temp-file body 读回解析
  - 超阈值 body 跳过
  - `multipart.filename` 进入检测链
- 检测与阻断：
  - parser 高置信命中
  - 豁免命中放行
  - 弱规则 + 高模型分仅升权
- 模式语义：
  - `shadow` 强制 allow
  - `assist` first-seen 才人工
  - `selective_enforce` 仅高置信未豁免阻断
- 豁免热更新：
  - Java 推送 `publish` 后无需 reload 生效
  - 非法 compiled 不推进 generation
  - 重复 key 导致加载失败
  - 部分节点失败时仅重试失败节点
- 自动化运营：
  - auto_suggest 触发与抑制
  - first-seen 仅首次入队
  - 历史模式自动决策
- 日志与入库：
  - Java ingest 按 checkpoint 恢复
  - `event_id` 幂等去重
  - `<=60s` 页面可见
- SGD 发布：
  - `candidate -> shadow_observe -> stable`
  - 门禁失败阻断晋级
  - 保持旧 stable
