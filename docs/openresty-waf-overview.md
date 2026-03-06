# OpenResty WAF 总览（流程骨架版）

本文档是第一阅读入口，目标是让你在短时间内理解：

- 整体架构
- 检测流程
- 硬拦截边界
- 运营自动化主线

详细实现、配置字段、日志 schema、测试门禁请看：
[OpenResty WAF 详细实现说明](./openresty-waf-implementation.md)。

联调、验收与 smoke 脚本入口请看：
[OpenResty WAF 联调与验证手册](./openresty-waf-validation.md)。

## 目录

- [1. 背景与目标](#1-背景与目标)
- [2. 核心结论](#2-核心结论)
- [3. 运行时主流程骨架（10步）](#3-运行时主流程骨架10步)
- [4. 三种模式语义](#4-三种模式语义)
- [5. 硬拦截边界](#5-硬拦截边界)
- [6. 运营自动化骨架](#6-运营自动化骨架)
- [7. SGD 生命周期骨架](#7-sgd-生命周期骨架)
- [8. 发布与回退骨架](#8-发布与回退骨架)
- [9. 性能与资源目标](#9-性能与资源目标)
- [10. 风险边界与非目标](#10-风险边界与非目标)
- [附录 A：名词表](#附录-a名词表)
- [附录 B：FAQ](#附录-bfaq)

## 1. 背景与目标

本方案面向反向代理场景，第一版只做 `SQLi + XSS`，核心目标：

- 可上线
- 可运营
- 低误拦
- 少人工操作
- 可回退

第一版不追求一次性覆盖全部 Web 攻击类型。

详细实现： [§0 摘要与范围](./openresty-waf-implementation.md#impl-scope)

## 2. 核心结论

1. 生产主链是 `libinjection + 精确豁免 + 轻量规则/弱启发式 + SGD辅助评分`。
2. `SGD` 不允许 `model-only block`。
3. `shadow` 阶段不逐条人工 review，使用模式聚类自动生成候选。
4. `high` 告警只对首次出现模式进入人工复核，历史模式自动处理。
5. 豁免支持热更新，不需要 `nginx reload`。
6. 检测超时固定 `fail-open`，不因超时阻断。
7. 规范化契约固定为 `norm-v1`，训练与推断必须一致。
8. `SGD` 发布采用指标门禁自动晋级，异常才人工介入。
9. 第一版硬拦截入口保持收敛，不扩大阻断面。
10. 运营与审核链路只使用 `MySQL 8.0+`，不引入 ES/ClickHouse。
11. 日志展示、候选审核、豁免发布全部在 Java 层完成。
12. OpenResty 不连数据库，只负责日志落盘与豁免快照接收。
13. 主拦截在 `access`，`log` 仅做信誉黑名单更新（影响后续请求）。
14. 规则、模型、主配置仍走正式发布与回退流程。
15. OpenResty 采用单入口配置，按 `interceptor/admin` 两个目录拆代码并用双 `server` 块分流。
16. OpenResty 与 Java 当前均以配置文件作为主配置入口，分别读取 `modules/openresty/conf/waf-config.json` 与 `modules/java-control-plane/conf/control-plane-config.json`。

详细实现： [§1 检测链](./openresty-waf-implementation.md#impl-pipeline)、[§3 豁免热更新](./openresty-waf-implementation.md#impl-exemption-hot-reload)、[§5 聚合与超时](./openresty-waf-implementation.md#impl-policy-aggregation)、[§6 SGD](./openresty-waf-implementation.md#impl-sgd)、[§8 Java 运营链路](./openresty-waf-implementation.md#impl-java-mysql)、[§11 运行手册](./openresty-waf-implementation.md#impl-runbook)、[联调与验证手册](./openresty-waf-validation.md)

## 3. 运行时主流程骨架（10步）

1. `access` 黑名单快速匹配（命中可直接拦截）
2. 请求信息选择（URI/query/白名单头/受控 body）
3. 统一规范化（`norm-v1`）
4. 字段切分
5. 高置信检测（`libinjection_sqli/xss`）
6. 精确豁免匹配（`signature_exact` -> `detector_field`）
7. 轻量规则与弱启发式
8. `SGD` 辅助评分（Lua FFI）
9. 策略聚合与动作执行（allow/log/block）
10. `log` 阶段输出日志并更新信誉黑名单（影响后续请求）

详细实现： [§1 检测链实现细则](./openresty-waf-implementation.md#impl-pipeline)

## 4. 三种模式语义

### `shadow`

- 执行完整检测链
- `enforced_action` 固定 `allow`
- 产出完整策略信号与样本
- 进入模式聚类统计并生成 `auto_suggested` 候选

### `assist`

- 执行完整检测链
- 默认不直接阻断新模式
- `high` 仅首次出现模式进入人工复核
- 历史 `benign_confirmed` / `attack_confirmed` 自动沿用历史判定

### `selective_enforce`

- 执行完整检测链
- 仅未豁免的高置信命中进入真实阻断
- 弱规则 + 高模型分默认仍不直接阻断

详细实现： [§1.4 模式语义](./openresty-waf-implementation.md#impl-modes)

## 5. 硬拦截边界

第一版硬拦截入口（默认）：

1. `libinjection` 命中
2. 当前请求未命中豁免
3. 处于 `selective_enforce`
4. 不在显式高误报字段保护范围
5. 未触发 `timeout_fail_open`

另一个硬拦截入口：

- `access` 黑名单命中（条目未过期）

默认不是硬拦截：

- `model_only`
- 单弱信号
- 弱规则 + 高模型分（未进增强阻断集）
- `shadow` 与 `assist` 中的普通命中

详细实现： [§5 聚合与动作矩阵](./openresty-waf-implementation.md#impl-policy-aggregation)

## 6. 运营自动化骨架

### 6.1 Shadow 自动候选

按模式键聚类并在窗口内自动生成 `auto_suggested` 候选，不逐条审告警。

### 6.2 First-seen 人工复核

人工只处理“首次出现模式”，不是处理所有 `high` 告警。
`first_seen_pattern` 由 Java ingest 入库时判定，OpenResty 热路径不做 first-seen 查询。

### 6.3 历史模式自动处理

- `benign_confirmed`：自动放行/豁免
- `attack_confirmed`：在 `selective_enforce` 自动进入阻断候选

### 6.4 Java 审核与存储边界

- 审核页面、审批动作、发布编排在 Java 层
- 运营数据仅存 `MySQL 8.0+`
- OpenResty 仅写 `NDJSON` + 接收发布接口

详细实现： [§4 模式记忆库与自动候选](./openresty-waf-implementation.md#impl-pattern-memory)、[§8 Java 运营链路](./openresty-waf-implementation.md#impl-java-mysql)

## 7. SGD 生命周期骨架

状态机：

- `candidate -> shadow_observe -> stable`

默认策略：

- 自动门禁晋级
- 指标达标自动升
- 指标异常不晋级并告警
- 异常时人工介入，不做常规人工审批

详细实现： [§6 SGD 训练/加载/发布门禁](./openresty-waf-implementation.md#impl-sgd)

## 8. 发布与回退骨架

### 通道 A：豁免热更新（高频）

- Java 审核通过后，以“已审批规则”为主源编译运行时快照
- 如指定 `authoring_source`，可用文件源覆盖默认编译入口
- Java 推送整包快照 + `generation` 到每个 OpenResty 节点
- 节点原子发布，worker 自动感知
- 只推进 `exemptions_generation`
- 回退时 `generation` 仍单调递增（旧快照以新代次重发）
- OpenResty 的 `/_waf/internal/exemptions/rollback` 默认不执行业务回退；真正回退由 Java 控制面重发历史快照完成

### 通道 B：正式发布（低频）

- 模型/规则/主策略发布
- 更新 `base_model_version/policy_version/ruleset_version`
- 支持版本回退

详细实现： [§3 豁免热更新](./openresty-waf-implementation.md#impl-exemption-hot-reload)、[§11 运行手册](./openresty-waf-implementation.md#impl-runbook)
开发顺序： [§12 开发实施顺序与工程组织](./openresty-waf-implementation.md#impl-dev-sequence)
联调与验证： [OpenResty WAF 联调与验证手册](./openresty-waf-validation.md)

## 9. 性能与资源目标

目标值（摘要）：

- 时延：`p95 < 2ms`，`p99 < 5ms`，硬上限 `< 10ms`
- 单请求额外内存：常规 `< 512KB`，大文本 `< 2MB`，硬上限 `< 32MB`
- 单 worker 额外常驻内存目标：`< 24MB`
- 支持平台：`Linux x86_64`、`Linux arm64`

详细实现： [§7 配置接口](./openresty-waf-implementation.md#impl-config)、[§10 测试与验收](./openresty-waf-implementation.md#impl-test-acceptance)

## 10. 风险边界与非目标

第一版不做：

- 上传文件内容扫描
- 无 `Content-Length` body 深度解析
- 大 body 全量检测
- 全能力 WAF（SSRF/RCE/路径穿越等）

同时明确：

- 本方案是“低误拦 + 可运营”的折中，不承诺覆盖所有业务上下文攻击

详细实现： [§2 规范化契约](./openresty-waf-implementation.md#impl-normalization)、[§10.7 安全边界](./openresty-waf-implementation.md#impl-scope-limits)

## 附录 A：名词表

- `pattern_key_v1`：
  `method | route_key | content_type | surface | field_selector | detector | signature_token`
- `pattern_key`：
  日志展示字段，对应 `pattern_key_v1` 的可读串
- `pattern_state`：
  `unknown | benign_confirmed | attack_confirmed`
- `candidate_status`：
  `auto_suggested | approved | rejected | expired`
- `candidate_reason`：
  `high_freq_benign_pattern | first_seen_resolved_benign | manual_override`
- `policy_version`：
  正式发布策略版本
- `exemptions_generation`：
  运行时热更新豁免代次

## 附录 B：FAQ

### Q1：为什么不默认自动批准豁免？

因为会放大投毒风险。默认只自动建议（`auto_suggested`），由客户批量确认。

### Q2：为什么 `high` 不全部人工看？

高流量场景噪音太大，无法运营。默认只人工处理首次出现模式。

### Q3：为什么 `SGD` 要自动门禁晋级？

客户通常不具备模型评审能力。用离线+影子指标门禁更稳、更可重复。

### Q4：为什么检测超时要 `fail-open`？

避免因安全链路资源抖动造成业务误阻断。超时事件仍会高优告警并可追踪。

### Q5：当前应该看哪份运行配置？

以代码里的 JSON 配置文件为准：

- OpenResty：`modules/openresty/conf/waf-config.json`
- Java：`modules/java-control-plane/conf/control-plane-config.json`
