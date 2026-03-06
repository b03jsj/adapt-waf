# OpenResty WAF 设计方案

> 说明：本文档已拆分为两份主入口文档，建议优先阅读：
> - [OpenResty WAF 总览（流程骨架版）](./openresty-waf-overview.md)
> - [OpenResty WAF 详细实现说明](./openresty-waf-implementation.md)
>
> 本文档保留为历史完整版/对照版，不再作为当前代码实现的规范源。
> 当前实现请以两份主入口文档和 `modules/shared-spec/` 契约为准。

## 1. 背景与目标

### 1.1 背景

当前已知问题是基于 `ModSecurity` 的负向规则方案容易产生较多误拦。误拦带来的直接后果不是单次告警不准，而是生产可用性下降、客户对安全防护失去信任、运维长期陷入规则调优和豁免维护。

本方案目标不是做一个覆盖全部 Web 攻击类型的大而全 WAF，而是先在 `OpenResty` 体系内落地一套能稳定上线、可持续运营、低误拦、可扩展的 `SQLi + XSS` 防护能力。

### 1.2 第一版目标

- 可上线
- 可运营
- 少人工调规则
- 低误拦
- 可扩展
- 可回退

### 1.3 第一版防护范围

- `SQLi`
- `XSS`

### 1.4 非目标

- 不追求一次性覆盖所有 Web 攻击
- 不在第一版处理 `SSRF`、`RCE`、`路径穿越`、`上传文件内容扫描` 等能力
- 不将 `SGD` 作为单独阻断引擎
- 不引入大型外部负向规则库作为生产阻断主链

## 2. 总体设计结论

本方案的明确设计结论如下：

- 不使用 `NAXSI` 作为生产阻断主链
- 不采用大型负向规则库作为核心
- 生产主链固定为：`libinjection + 精确豁免匹配 + 自有轻量策略引擎/弱启发式 + SGD辅助评分`
- `SGD` 不允许 `model-only block`
- `shadow` 期采用模式聚类自动生成豁免候选，不做逐条人工 review
- `high` 告警默认只对“首次出现模式”触发人工复核
- `SGD` 发布采用指标门禁自动晋级，异常时才人工介入
- 采集使用 `OpenResty + Lua`
- 训练使用 `Java` 一次性批处理程序
- 支持版本化发布与快速回退
- 请求体只做受控解析，不做全量无界解析

## 3. 为什么不采用 ModSecurity/NAXSI 路线

### 3.1 不采用 ModSecurity/CRS 路线的原因

`ModSecurity/CRS` 的优点是覆盖面广，但它的核心代价是大量负向规则和持续调优。对于以低误拦、少人工维护为目标的生产环境，这种模式容易演化成长期维护负担：

- 规则覆盖越广，误拦概率越高
- 误拦一旦出现，往往需要按接口、按字段持续豁免
- 规则理解和回归验证成本高
- 线上故障容易表现为“业务被安全规则拦住但不易解释”

### 3.2 不采用 NAXSI 作为生产阻断主链的原因

`NAXSI` 虽然比 `ModSecurity` 更轻，但其工作模式本质仍偏向：

- `drop-by-default`
- 依赖持续补充 `whitelist/accept`

这与本方案“可稳定上线、少人工调规则”的目标冲突。第一版必须选择一个更可控、更容易解释、误拦面更小的基础架构，因此不将 `NAXSI` 放入阻断主链。

### 3.3 替代路线

替代路线不是“完全不要规则”，而是将规则能力收缩为：

- `libinjection` 提供高置信基础检测
- 精确豁免列表处理真实误报
- 自有轻量小规则集和弱启发式处理少量绕过与告警排序
- `SGD` 只参与辅助评分

## 4. 第一版能力范围

### 4.1 支持范围

第一版支持以下能力：

- `SQLi`
- `XSS`

### 4.2 支持的输入面

- `URI`
- `query` 参数
- 白名单 `headers`
- 小型文本 `body`

### 4.3 暂不支持或不在第一版范围内

- 上传文件内容扫描
- 大 body 全量检测
- 无 `Content-Length` body 解析
- `SSRF`
- `RCE`
- `路径穿越`
- `命令注入`
- `Bot` 行为分析

## 5. 运行时总体架构

### 5.1 热路径定义

运行时热路径固定为：

1. 请求信息选择
2. 统一规范化
3. 字段切分
4. 高置信检测
5. 精确豁免匹配
6. 轻量规则与弱启发式检测
7. `SGD` 辅助评分
8. 策略聚合
9. 告警分级与动作执行
10. 结构化日志

### 5.2 组件职责

- `OpenResty`
  - 请求接入
  - 请求采集
  - 规范化
  - 轻量策略执行
  - 最终阻断/放行
- `Lua`
  - 采集逻辑
  - 配置装配
  - 策略编排
  - 轻量规则执行
  - 样本结构化输出
- `C`
  - 运行时核心检测能力
  - `libinjection` 接入
  - 高性能辅助模块
- `Java` 批处理程序
  - 夜间训练
  - 模型评估
  - 候选模型产出
  - 版本工件生成

### 5.3 架构原则

- 热路径只允许轻量同步能力
- 训练不进入 `worker` 进程
- 配置和版本切换必须支持快速回退
- 所有新增能力必须沿统一插件接口扩展

## 6. 检测链路设计

### 6.1 核心检测组件

#### `libinjection_sqli`

- 用于高置信 `SQLi` 检测
- 作为第一层基础阻断信号

#### `libinjection_xss`

- 用于高置信 `XSS` 检测
- 作为第一层基础阻断信号

补充原则如下：

- `libinjection` 是第一层高置信信号，但不是唯一兜底
- 对 `libinjection` 已知薄弱区间，必须由以下能力共同兜底：
  - 已知绕过专项小规则
  - 弱启发式信号
  - `SGD` 辅助评分
  - 模式记忆与抽检复核
- 兜底能力只能“部分覆盖” `libinjection` 漏报，不能宣称完全替代

#### 精确豁免匹配

- 用于处理已确认误报（人工确认或候选批量确认）
- 作为第一版误报治理主机制
- 不依赖业务方提前提供接口契约

豁免匹配粒度固定至少包括：

- `method`
- `route_key` 或 `normalized_uri`
- `content_type`
- `surface`
- `field_name` 或 `json_path`
- `detector`
- `signature`

豁免条目必须新增：

- `match_scope`
  - `signature_exact`
  - `detector_field`

默认规则如下：

- 首次建立豁免时默认使用 `signature_exact`
- 仅对显式批准的高误报字段允许使用 `detector_field`
- `detector_field` 只允许用于：
  - `libinjection_sqli`
  - `libinjection_xss`
- `detector_field` 不允许用于：
  - `rule_engine`
  - `sgd_*`

豁免命中后的固定动作如下：

- 不阻断
- 保留告警日志
- 标记 `exemption_applied = true`
- 进入误报审计链路

明确禁止以下粗粒度豁免：

- 整个 URI 免检
- 整类 `SQLi/XSS` 免检
- 仅按字段名全局免检
- 仅按 route 全局免检

豁免热更新必须固定为：

- 豁免是第一版唯一允许高频热更新的策略工件
- 修改豁免后不需要 `nginx reload`
- 运行时只热加载编译产物：
  - `exemptions.compiled.json`
- 人工维护格式仍为：
  - `exemptions.yaml`

运行时加载时机固定如下：

- `init_by_lua*`
  - 初始化 `lua_shared_dict waf_control` 中的元数据键
  - 不加载完整豁免表
- `init_worker_by_lua*`
  - 每个 worker 加载本地只读豁免快照
  - 启动热更新定时器

热更新机制固定如下：

- `worker 0` 作为 leader，每 `5s` 检查：
  - `exemptions.compiled.json`
  - `mtime`
  - `size`
  - `sha256`
- 所有 worker 每 `1s` 检查 `lua_shared_dict` 中的目标 generation
- generation 变化时：
  - 读取 `compiled.json`
  - 校验 `sha256`
  - 构建本地匹配索引
  - 原子替换本地快照引用

请求热路径固定只读：

- `worker_local.exemptions_snapshot`

请求热路径明确禁止：

- 读取豁免文件
- 运行时解析 YAML
- 从 `lua_shared_dict` 读取完整豁免表

#### 自有轻量策略引擎与弱启发式

- 仅负责少量弱规则与绕过迹象检测
- 不采用大规模规则库
- 优先使用字符串扫描和字符级判断
- 同时负责弱启发式信号：
  - 长度异常
  - 字符集异常
  - 控制字符存在
  - 分隔符密度异常
  - SQL 关键字密集排列
  - URL 编码层数异常
  - HTML entity / Unicode escape 混淆迹象
  - 重复参数和结构异常

弱启发式只能用于：

- 增加 `weak_signal_score`
- 提升告警优先级
- 辅助样本分层
- 与 `SGD` 组合形成 `suspected_attack`

弱启发式默认不能单独阻断。

#### 可选接口约束

- 默认不进入第一版主路径
- 仅在客户后续明确提供接口契约时作为可选增强能力接入
- 不作为第一版可上线前提

#### `sgd_sqli`

- 用于 `SQLi` 辅助评分
- 不单独阻断

#### `sgd_xss`

- 用于 `XSS` 辅助评分
- 不单独阻断

### 6.2 阻断规则

- 高置信解析器命中且未命中精确豁免时，才可进入阻断候选
- `SGD` 不允许 `model-only block`
- 弱规则只有在和其它信号组合时才允许升权
- 富文本、模板、代码片段类字段默认不允许仅凭弱规则或模型高分直接阻断
- 第一版默认不允许“弱规则 + 高模型分”直接阻断，除非后续专项批准进入增强阻断集

### 6.3 策略聚合规则

建议的聚合逻辑如下：

- `libinjection` 命中且未豁免：
  - `shadow` 下进入模式聚类统计与候选生成
  - `assist` 下仅当“首次出现模式”时进入人工复核队列
  - `selective_enforce` 下进入高优先级阻断候选
- `libinjection` 命中且已豁免：
  - 放行
  - 保留高优先级告警和审计日志
- 弱规则命中 + 高模型分：
  - 中高优先级告警候选
  - 默认不阻断
- 仅模型高分：
  - 只记录日志，不阻断

`policy_decision_basis` 的固定取值如下：

- `parser_hit_shadow`
- `parser_hit_assist`
- `parser_hit_assist_first_seen`
- `parser_hit_assist_known_benign`
- `parser_hit_assist_known_attack`
- `parser_hit_block`
- `parser_hit_exempted_exact`
- `parser_hit_exempted_detector_field`
- `parser_hit_auto_suggested`
- `weak_combo_only`
- `model_only`
- `timeout_fail_open`

### 6.4 运行模式语义

配置项 `mode: shadow | assist | selective_enforce` 必须有严格、不可歧义的运行语义。

#### `shadow`

- 执行完整检测链：
  - 规范化
  - 高置信检测
  - 精确豁免匹配
  - 轻量规则与弱启发式
  - `SGD`
  - 策略聚合
- 生成完整的 `decision_candidate`
- 输出完整日志和样本
- 实际执行动作固定为：
  - `allow`
- 所有高置信命中进入模式聚类统计
- 自动生成 `auto_suggested` 豁免候选
- 该模式用于建立首批候选列表，不要求逐条人工 review

#### `assist`

- 执行完整检测链
- 默认不对新发现模式直接阻断
- 未豁免的 `libinjection` 命中：
  - 若为首次出现模式：
    - 记录 `critical/high` 告警
    - 进入高优先级人工复核队列
  - 若为历史 `benign_confirmed` 模式：
    - 自动按既有豁免或放行策略处理
  - 若为历史 `attack_confirmed` 模式：
    - 自动标记高风险并进入阻断候选评估
  - 默认不对新模式直接阻断
- 以下信号在 `assist` 模式下只记录，不阻断：
  - `libinjection` 命中且已豁免
  - 单独弱规则命中
  - 弱规则 + 高模型分
  - 仅模型高分

用途：

- 作为从 `shadow` 过渡到真实阻断的观察阶段
- 收敛误报
- 把人工复核收敛到“首次出现模式”

#### `selective_enforce`

- 执行完整检测链
- 满足以下条件时才允许真实阻断：
  - `libinjection` 命中
  - 当前请求未命中精确豁免
  - 不属于显式高误报字段类别的保护范围
- 弱规则 + `SGD` 组合默认仍不直接阻断
- 未被显式批准进入增强阻断范围的信号，行为必须退化为 `assist`
- `model-only block` 在该模式下仍然禁止

用途：

- 对未被证明为误报的高置信 parser 命中实施正式阻断
- 在保持可回退前提下逐步提高生产拦截强度

#### 模式实现要求

- 所有模式都必须输出：
  - `decision_candidate`
  - `enforced_action`
- `shadow` 模式中：
  - `decision_candidate` 可为 `block`
  - 但 `enforced_action` 必须为 `allow`
- `assist` 模式中：
  - `decision_candidate` 可为 `block`
  - 但 `enforced_action` 默认必须为 `allow`
- `selective_enforce` 与 `assist` 的核心差异，在于是否允许“未豁免的高置信 parser 命中”进入真实阻断
- `model-only block` 在任何模式下都必须为 `false`

### 6.4.1 模式记忆库（Pattern Memory）

为减少人工操作，第一版必须引入模式记忆库，主键固定为：

- `method + route_key + surface + field_name/json_path + detector + signature`

状态固定为：

- `unknown`
- `benign_confirmed`
- `attack_confirmed`

附加统计固定包括：

- `first_seen`
- `last_seen`
- `hit_count`
- `last_decision`

处理规则固定为：

- `unknown`：
  - 仅首次出现进入人工复核队列
- `benign_confirmed`：
  - 自动沿用历史放行/豁免策略
- `attack_confirmed`：
  - 在 `selective_enforce` 下自动进入阻断候选

### 6.5 告警分级与威胁分类

运行时动作不能只区分“阻断”和“记日志”，必须同时区分告警等级和威胁分类。

第一版固定输出以下字段：

- `threat_classification`
  - `confirmed_attack`
  - `suspected_attack`
  - `sample_only`
  - `none`
- `alert_level`
  - `critical`
  - `high`
  - `low`
  - `none`

分级规则固定如下：

- `confirmed_attack + critical`
  - `libinjection_sqli` 命中、未豁免，且在 `selective_enforce` 下真实阻断
  - `libinjection_xss` 命中、未豁免，且在 `selective_enforce` 下真实阻断
  - 已批准进入增强阻断范围的弱规则组合被真实阻断
- `suspected_attack + high`
  - `libinjection` 命中但当前模式不阻断
  - `libinjection` 命中且已命中精确豁免
  - 弱规则 + 高 `SGD` 分数，但未达到真实阻断门槛
  - 多弱信号叠加 + 高 `SGD` 分数，但当前模式或路由策略不允许阻断
  - `libinjection` 未命中，但出现已知绕过特征组合
- `sample_only + low`
  - 仅 `SGD` 高分
  - 单条弱规则命中但无其它支撑信号
  - 仅用于样本积累和低优先级观察
- `none + none`
  - 无告警价值的普通放行请求

运营语义固定如下：

- `critical`
  - 进入阻断告警流
  - 默认要求人工复盘
- `high`
  - 默认只对“首次出现模式”进入人工复核队列
  - 历史已知模式自动沿用记忆库策略
  - 默认不阻断
- `low`
  - 不进入人工实时复核主队列
  - 仅用于样本回流、周期性抽样复核和策略调优
- `none`
  - 不输出告警日志，只在开启 trace 或命中采样时保留

这样做的目的如下：

- 把“已确认攻击”和“疑似攻击”从日志层面区分开
- 降低运营告警噪音
- 让模型反馈循环只关注高价值事件
- 将人工操作从“逐事件处理”降为“首次模式处理 + 批量确认”

### 6.6 timeout 回退语义

`hard_timeout_ms` 固定定义为整个 WAF 检测链的请求级硬预算。

预算检查点固定为：

1. 规范化前
2. 高置信检测前
3. 精确豁免匹配前
4. 轻量规则与弱启发式前
5. `SGD` 打分前
6. 策略聚合前

任一检查点发现：

- `elapsed_ms > hard_timeout_ms`

都必须立即中止后续检测流程，并固定执行：

- `decision_candidate = allow`
- `enforced_action = allow`
- `final_action = allow`
- `policy_decision_basis = timeout_fail_open`
- `alert_level = high`
- `threat_classification = suspected_attack`
- `budget_exhausted = true`

同时必须记录：

- `timeout_stage`
- `elapsed_ms`
- `hard_timeout_ms`
- `detector_stage_reached`

默认策略固定为：

- `timeout_policy = fail_open`

明确禁止：

- 因检测超时阻断请求
- 因“前面已经命中过部分信号”就在超时后直接阻断

## 7. 请求采集与 Body 解析策略

### 7.1 总体原则

请求采集采用“轻元数据默认采集，body 受控解析”的原则。真正的风险点在 `body`，不是 `uri`。`uri`、`method`、少量头部和有限 query 参数成本较低；大文本 body、`multipart` 和临时文件 body 才是内存和时延的主要风险。

本方案目标不是“绝对最小内存”，而是“有边界、可预测、可控”。

### 7.2 永久采集项

以下字段始终采集：

- `uri`
- `method`
- `host`
- `content-type`
- `content-length`
- 白名单请求头
- 限量 `query` 参数

### 7.3 Query 参数采集约束

- 只解析前 `max_query_args` 个参数
- 总字节数不超过 `max_query_bytes`
- 超限后停止展开，并记录超限标记

### 7.4 Header 采集约束

只采集白名单头，默认包括：

- `content-type`
- `content-length`
- `user-agent`
- `referer`

默认不采集全集 headers。

### 7.5 Body 解析白名单

只解析以下 `Content-Type`：

- `application/json`
- `application/x-www-form-urlencoded`
- `text/plain`

且必须同时满足：

- `Content-Length` 存在
- `Content-Length <= body_parse_max_bytes`

### 7.6 默认值与上限

- 默认 `body_parse_max_bytes = 128KB`
- 可配置
- 硬上限不超过 `1MB`

### 7.7 大包和特殊包处理策略

- `Content-Length` 缺失：
  - 不解析 body
- `Content-Length` 超过阈值：
  - 只记元数据
- `multipart/form-data`：
  - 只检查元数据和文本字段
  - 不检查文件内容
- body 已落盘到临时文件：
  - 仅在 `Content-Length` 低于阈值时允许读回解析

### 7.8 JSON 解析策略

- 仅提取字符串字段用于检测
- 限制最大字段数
- 限制最大嵌套层级
- 限制单字段最大字符串长度
- 超限时停止深入解析

### 7.9 Form 解析策略

- 仅解析字段名和值
- 限制最大字段数
- 限制单字段最大长度
- 限制总解析字节数

### 7.10 Multipart 策略

第一版只处理：

- 请求元数据
- 文件名
- part 的 `Content-Type`
- 文本字段

第一版不处理：

- 文件内容字节
- 图片、压缩包、文档内容

补充约束如下：

- `multipart.filename` 必须被视为普通文本字段，而不是只采集不检测
- `multipart.filename` 必须进入同一条检测链：
  - 统一规范化
  - `libinjection`
  - 精确豁免匹配
  - 自有轻量规则与弱启发式
  - `SGD` 辅助评分
- `multipart.filename` 默认最大检测长度建议为 `512 bytes`
- 超过 `multipart_filename_max_bytes` 时：
  - 截断检测
  - 记录截断标记
- `multipart.filename` 的字段类型标识固定为：
  - `multipart_filename`
- `multipart.filename` 的高置信命中允许进入阻断候选

这样做的原因是：

- 文件名本身可能成为 `SQLi/XSS` 注入载体
- 文件名经常会被日志、管理后台、文件列表、通知消息和页面展示直接引用
- 如果只采集文件名而不检测，就会形成已知覆盖缺口

### 7.11 内存风险结论

这个问题确实存在，但通过以下边界可以控制：

- 白名单 `Content-Type`
- 必须存在 `Content-Length`
- 解析大小阈值
- 对大包直接跳过 body
- 对上传文件不做内容级解析

### 7.12 规范化策略

规范化是整个检测链路里最容易引发误报和漏报的节点。第一版必须显式区分：

- `raw_value`
  - 字段抽取完成后、进入检测前的原始字段值
- `normalized_sqli_value`
  - 面向 `SQLi` 检测的规范化结果
- `normalized_xss_value`
  - 面向 `XSS` 检测的规范化结果

这里的 `raw_value` 指“字段抽取层看到的值”，而不是必须保留原始 HTTP 字节串。  
例如：

- `query/form/multipart filename`：
  - `raw_value` 为字段抽取后的原值
- `JSON`：
  - `raw_value` 为 JSON 解析器取出的字符串值

#### 7.12.1 URL decode 策略

URL decode 不是对所有字段统一无差别执行，而是按输入面执行。

默认规则如下：

- `query`
- `application/x-www-form-urlencoded`
- `multipart.filename`
  - URL decode 最多执行 `2` 次
- `application/json`
- `text/plain`
- 普通 `headers`
  - 默认不执行 URL decode

停止条件如下：

- 到达 `url_decode_max_passes`
- 当前一轮不再发生有效解码
- 出现非法 `%xx` 片段时停止继续解码，并记录异常标记

第一版默认行为：

- `url_decode_max_passes = 2`
- 例子 `%2527`：
  - 第一次解码为 `%27`
  - 第二次解码为 `'`

设计原因：

- 对 `query/form/multipart filename`，双重编码是现实攻击中常见手法
- 对 `JSON/text/plain/header` 默认不做 URL decode，可以降低把本来不会被业务再次解码的内容误判成攻击的风险

#### 7.12.1.a `text/*` 收敛策略

第一版不使用宽泛的 `text/*` 白名单，默认只允许：

- `text/plain`

以下类型默认不解析，只有业务明确批准后才允许单独加入白名单：

- `text/html`
- `text/xml`
- `text/csv`
- `text/event-stream`

设计原因如下：

- `text/*` 子类型差异较大
- `text/xml` 和 `text/html` 的解析语义明显复杂于 `text/plain`
- 对 `SQLi/XSS` 来说，默认放开全部 `text/*` 会扩大误报面和解析复杂度

#### 7.12.2 HTML entity decode 策略

HTML entity decode 只用于 `XSS` 视图，不用于 `SQLi` 视图。

默认规则如下：

- `normalized_xss_value`
  - 在 URL decode 之后执行 HTML entity decode
  - 最多执行 `2` 次
- `normalized_sqli_value`
  - 不执行 HTML entity decode

设计原因：

- HTML entity decode 对 `XSS` 检测是必要能力
- 对 `SQLi` 做 HTML entity decode 会扩大误报面，且不符合多数 SQL 解释链路

#### 7.12.3 大小写与空白处理

第一版默认规则如下：

- `libinjection` 的输入保留解码后的原字符结构，不做激进改写
- 轻量字符串规则和 `SGD` 特征提取使用 ASCII 小写视图
- 连续 ASCII 空白允许折叠为单空格，但必须只作用于：
  - 轻量规则
  - `SGD` 特征提取
- 不得在规范化阶段删除：
  - 引号
  - 注释符
  - 括号
  - 比较符
  - 标签分隔符

#### 7.12.4 Unicode 归一化策略

第一版默认不做 `NFC/NFD/NFKC/NFKD` 归一化。

明确规则如下：

- `unicode_normalization = none`
- 只做 UTF-8 合法性校验
- 遇到非法字节序列时：
  - 保留原值用于日志
  - 记录 `invalid_utf8` 标记
  - 不继续做 Unicode 归一化

设计原因：

- Unicode 归一化容易改变原始语义
- 第一版优先避免因为字符折叠带来的额外误报
- 如未来需要处理 Unicode 混淆攻击，应作为单独能力扩展

#### 7.12.5 规范化顺序

第一版固定顺序如下：

1. 字段抽取
2. 生成 `raw_value`
3. 按输入面决定是否执行 URL decode
4. 生成解码后的中间视图
5. 面向 `XSS` 执行 HTML entity decode
6. 生成：
  - `normalized_sqli_value`
  - `normalized_xss_value`
7. 对轻量规则和 `SGD` 生成小写/空白折叠视图

#### 7.12.6 日志追溯要求

为保证误报分析和样本回放，运行时日志和样本日志都必须区分：

- `raw_value`
- `normalized_sqli_value`
- `normalized_xss_value`
- `normalization_steps`
- `url_decode_passes`
- `html_entity_decode_passes`

同时增加以下控制项：

- `log_value_max_bytes`
  - 默认 `512`
- `raw_value_truncated`
- `normalized_value_truncated`

日志必须能回答以下问题：

- 原始字段值是什么
- 做了几次 URL decode
- 是否做了 HTML entity decode
- 最终送给 `SQLi/XSS` 检测的值分别是什么

#### 7.12.7 `normalization_profile` 契约

`normalization_profile` 不是注释字段，而是训练与推断一致性的正式契约。

第一版固定激活：

- `active_profile = norm-v1`

`norm-v1` 的具体定义如下：

- surface 级 URL decode：
  - `query = 2`
  - `form = 2`
  - `multipart_filename = 2`
  - `json = 0`
  - `text/plain = 0`
  - `header = 0`
  - `multipart_text = 0`
- `XSS` 视图：
  - HTML entity decode 最多 `2` 次
- `SQLi` 视图：
  - 不做 HTML entity decode
- Unicode：
  - `unicode_normalization = none`
  - 只做 UTF-8 合法性校验
- 模型和弱规则输入视图：
  - ASCII 小写化
  - 连续 ASCII 空白折叠为单空格
  - `model_feature_max_bytes = 2048`

每个字段必须固定生成以下视图：

- `raw_value`
- `normalized_sqli_value`
- `normalized_xss_value`
- `model_sqli_input`
- `model_xss_input`

关系固定如下：

- `normalized_sqli_value`
  - 按 `norm-v1` 做 surface 级 URL decode
  - 不做 HTML entity decode
- `normalized_xss_value`
  - 按 `norm-v1` 做 surface 级 URL decode
  - 再做 XSS 视图的 HTML entity decode
- `model_sqli_input`
  - `normalized_sqli_value` 再做 ASCII 小写、空白折叠和 `2048 bytes` 截断
- `model_xss_input`
  - `normalized_xss_value` 再做 ASCII 小写、空白折叠和 `2048 bytes` 截断

`Java` 训练、`Lua` scorer、弱规则和样本回放都必须基于同一 `normalization_profile`。不允许各自实现不同的规范化逻辑。

## 8. 规则与检测能力设计

### 8.1 检测与策略来源

第一版不引入大型外部规则库。检测与策略来源固定为：

- `libinjection`
- 精确豁免列表
- 自有固定小规则集
- 弱启发式信号
- 可选接口约束

其中：

- 精确豁免列表是第一版误报治理主机制
- 可选接口约束默认关闭，不作为第一版上线前提

### 8.2 精确豁免设计原则

第一版豁免列表必须满足以下要求：

- 只允许对已确认误报建立豁免：
  - 人工单条确认
  - 或 `auto_suggested` 候选批量确认
- 必须精确到：
  - `method`
  - `route_key`
  - `content_type`
  - `surface`
  - `field_name/json_path`
  - `detector`
  - `signature/rule_id`
- 必须保留：
  - 创建人
  - 创建时间
  - 误报来源事件
  - 变更审计记录

明确禁止：

- 全局 route 豁免
- 全局 detector 豁免
- 仅按字段名的全局豁免
- 因单次误报关闭整类检测

豁免的匹配范围固定采用：

- `match_scope = signature_exact`
- `match_scope = detector_field`

默认规则如下：

- 首次建立豁免默认使用 `signature_exact`
- `signature_exact` 必须匹配：
  - `method`
  - `route_key`
  - `content_type`
  - `surface`
  - `field_name/json_path`
  - `detector`
  - `signature/rule_id`
- `detector_field` 只匹配：
  - `method`
  - `route_key`
  - `content_type`
  - `surface`
  - `field_name/json_path`
  - `detector`

`detector_field` 的适用范围固定为：

- 只允许用于：
  - `libinjection_sqli`
  - `libinjection_xss`
- 不允许用于：
  - `rule_engine`
  - `sgd_*`

`detector_field` 的启用条件固定为：

- 必须显式审批
- 至少有 `2` 个已确认误报事件作为依据
- 必须填写：
  - `scope_relaxation_approved = true`
  - `scope_relaxation_reason`
  - `source_event_ids`
- `expires_at` 必须存在
- 默认 TTL 为 `30 days`

### 8.3 豁免热加载与运行时索引

第一版固定采用热加载，不需要 `nginx reload`。

工件格式固定区分为：

- 人工维护格式：
  - `exemptions.yaml`
- 运行时热加载格式：
  - `exemptions.compiled.json`

### 8.3.1 豁免发布操作路径

`exemptions.compiled.json` 不是手工编辑文件，必须由编译步骤生成。固定操作路径如下：

1. 安全运营在审核流程中确认误报，并修改：
   - `exemptions.yaml`
2. 执行编译工具：
   - `waf-exempt compile --in exemptions.yaml --out exemptions.compiled.json.tmp.<ts>`
3. 编译工具执行校验：
   - YAML 语法校验
   - schema 校验
   - 重复 key 校验
   - `match_scope` 合法性校验
   - `detector_field` 约束校验（审批、TTL、检测器范围）
4. 校验通过后，输出临时文件并执行原子 `rename`：
   - `exemptions.compiled.json.tmp.<ts> -> exemptions.compiled.json`
5. worker 自动感知并热加载生效，无需 `nginx reload`

编译失败时固定行为：

- 编译命令返回非 `0`
- 输出可定位的错误信息（至少包含条目 id 或行号）
- 不覆盖当前 `exemptions.compiled.json`
- 不推进 `exemptions.target_generation`
- 旧豁免快照继续服务

实现要求：

- 编译步骤可以作为独立 CLI，也可以作为发布流水线中的固定步骤
- 生产侧只允许接收编译后的 `exemptions.compiled.json`
- 禁止直接手工覆盖运行时 `compiled.json`

### 8.3.2 Shadow 期自动候选生成（人工最小化）

第一版 `shadow` 期不做逐条人工 review，固定采用模式聚类自动候选。

聚类键固定为：

- `method + route_key + surface + field_name/json_path + detector + signature`

聚合窗口默认：

- `N = 7 days`

自动候选触发条件（全部满足）：

1. 命中次数 `hits >= 200`
2. 业务接受率 `2xx_ratio >= 99.5%`
3. 来源分散：
   - `unique_ip >= 20`
   - `ip_entropy >= 2.5`
   - `single_ip_ratio < 0.2`
4. 扫描器特征低于阈值：
   - 已知扫描器 `ua/ip` 占比未超阈值
5. 历史无攻击标签冲突：
   - 该聚类键未标记为 `attack_confirmed`

满足条件后生成豁免候选：

- `candidate_status = auto_suggested`
- `candidate_reason = high_freq_benign_pattern`

固定约束：

- `auto_suggested` 候选不自动生效
- 客户操作以“批量确认候选”为主，不逐条处理原始告警
- 批量确认后才进入豁免编译发布路径

运行时加载时机固定如下：

- `init_by_lua*`
  - 初始化 `lua_shared_dict waf_control` 中的元数据键
  - 不加载完整豁免表
- `init_worker_by_lua*`
  - 每个 worker 加载当前本地只读豁免快照
  - 启动热更新定时器

热更新机制固定如下：

- `worker 0` 作为 leader，每 `5s` 检查：
  - `mtime`
  - `size`
  - `sha256`
- 所有 worker 每 `1s` 检查 `target_generation`
- generation 变化时：
  - 读取 `exemptions.compiled.json`
  - 校验 `sha256`
  - 解析并构建本地匹配索引
  - 原子替换本地快照引用

每个 worker 必须把豁免编译成索引，不得顺序扫描整表。推荐索引固定为：

- `exact_index`
  - key:
    - `method|route_key|content_type|surface|field_name|json_path|detector|signature`
- `detector_field_index`
  - key:
    - `method|route_key|content_type|surface|field_name|json_path|detector`

匹配顺序固定为：

1. `signature_exact`
2. `detector_field`
3. no match

冲突规则固定如下：

- 同一 key 出现重复条目时，加载失败
- 不允许依赖“后者覆盖前者”

失败处理固定如下：

- 任一 worker 热更新失败：
  - 保留旧快照继续服务
  - 记录 `alert_log`
  - 标记：
    - `exemptions_load_failed = true`
    - `exemptions_failed_generation`
- leader 发布失败：
  - 不推进 generation
  - 所有 worker 保持旧快照
  - 记录高优先级配置告警

SLO 固定为：

- 新豁免文件从原子发布到全 worker 生效目标 `<= 10s`

### 8.4 自有小规则集设计原则

规则重点覆盖：

- URL 编码和双重编码异常
- HTML entity / Unicode escape 混淆
- SQL 注释拆分与空白绕过
- 危险标签和危险协议片段
- 明显异常的连接、拼接和闭合结构

### 8.5 弱启发式信号设计原则

第一版弱启发式固定覆盖：

- 单字段长度异常
- 字符集异常
- 控制字符存在
- 分隔符密度异常
- SQL 关键字密集排列
- URL 编码层数异常
- 重复参数或结构异常

这些信号只允许用于：

- 告警排序
- 样本分层
- 与弱规则或 `SGD` 组合形成 `suspected_attack`

这些信号默认不允许单独阻断。

### 8.6 实现优先级

优先使用：

- 普通字符串扫描
- 字符级状态机
- 长度规则
- 字符集规则
- 计数规则

少量必要场景才使用 `Lua regex`。

### 8.7 Lua regex 约束

- `Lua regex` 可用，但只能少量使用
- 必须启用：
  - `pcre_jit on;`
  - `ngx.re.find(..., "jo")` 或等价缓存/JIT策略
- 总 regex 规则数必须受控
- 禁止堆大量泛化 regex
- 禁止对大 body 做多轮全量 regex 扫描

### 8.8 规则规模控制

建议第一版控制在：

- 总规则数 `<= 40`
- 其中 regex 规则数 `<= 15`

### 8.9 规则新增要求

每条新增规则或启发式必须具备：

- 明确的命中目标
- 明确的误报边界
- 回归测试样本
- 上线前压测结果

## 9. SGD 模型设计与训练流程

### 9.1 模型定位

- `SGD` 只做辅助评分
- 不单独阻断
- 不在 `worker` 或 `ngx.timer` 中训练

### 9.2 特征设计

- `char 3-5 gram`
- 哈希特征
- 不使用传统 `word bag-of-words`

### 9.3 模型划分

- `sgd_sqli`
- `sgd_xss`

### 9.4 样本来源

正样本来源：

- 合成攻击样本
- 公开 payload
- 真实确认攻击

负样本来源：

- 经过过滤门的未拦截流量
- `hard_negative`

必须明确：

- `未被拦截` 不直接等于 `clean_confirmed`

### 9.5 过滤门

未拦截流量只有满足以下条件才可进入负样本候选池：

- 未命中高置信检测
- 未达到高风险阻断阈值
- 不来自已知扫描器或异常来源
- 被业务正常接受
- 不存在明显混淆异常

### 9.6 采样率与采样策略

第一版不对所有正常流量做全量采样，而采用分层采样策略。

采样率固定分为以下几档：

- 高价值攻击样本：
  - `100%`
- 高价值负样本：
  - `100%`
- 普通正常样本：
  - 默认 `1%`
  - 可配置范围 `0.1% ~ 5%`

其中：

- 高价值攻击样本包括：
  - 已阻断请求
  - 高置信解析器命中请求
  - 人工确认攻击请求
- 高价值负样本包括：
  - 命中弱规则但最终放行的请求
  - `hard_negative` 画像字段
  - 富文本、代码、模板类字段
  - `multipart_filename`
  - 需要重点抑制误报的业务字段
- 普通正常样本指：
  - 通过过滤门、且没有弱信号的普通已放行请求

为避免流量倾斜和样本爆炸，必须增加以下约束：

- 普通正常样本使用确定性哈希采样
- 默认按 `route + field + normalized_value_digest` 做稳定采样
- 必须支持按路由和字段设置采样上限
- 必须支持按时间窗口设置最小采样配额

建议默认值如下：

- `clean_sample_rate = 1%`
- `weak_signal_allow_sample_rate = 100%`
- `hard_negative_sample_rate = 100%`
- `per_route_field_clean_cap_per_hour = 1000`
- `per_route_field_clean_floor_per_hour = 20`

设计意图如下：

- 攻击样本稀缺，必须全量保留
- 真正有训练价值的负样本，不是普通干净流量，而是容易误报的负样本
- 普通正常样本只需要保留足够覆盖，不需要全量

### 9.7 采样与训练链路

`OpenResty + Lua` 负责：

- 采样
- 基础过滤
- 结构化落盘

`Java` 一次性批处理程序负责：

- 夜间训练
- 模型评估
- 产出候选模型
- 产出版本工件

### 9.8 SGD 权重导出与加载方案

`SGD` 的运行时 scorer 后端必须明确。第一版固定为：

- `OpenResty + LuaJIT FFI`
- 仅当出现明确性能或内存问题时，才升级为 `C + mmap`
- 第一版不允许同时维护两套生产 scorer

#### 9.8.1 模型工件结构

训练程序由 `Java` 导出版本化模型工件，每个模型固定为两文件：

1. `manifest.json`
2. `weights.bin`

每个攻击类型一个独立模型目录：

- `sqli`
- `xss`

第一版和未来 `C + mmap` scorer 都必须读取同一模型格式，不允许后续为了切换 scorer 重定义训练产物。

#### 9.8.2 `weights.bin` 格式

`weights.bin` 固定为：

- `float32`
- `little-endian`
- flat binary array
- 长度等于 `hash_dim`

内容只包含：

- 权重数组 `weights`

明确不包含：

- 词典
- 稀疏索引
- JSON 包装
- Lua 代码
- 阈值配置

#### 9.8.3 `manifest.json` 格式

`manifest.json` 固定包含：

- `format`
- `attack_type`
- `hash_dim`
- `ngram_min`
- `ngram_max`
- `dtype`
- `bias`
- `weights_file`
- `weights_sha256`
- `model_version`
- `trained_at`
- `parent_version`
- `normalization_profile`

建议结构固定为：

```json
{
  "format": "sgd-linear-v1",
  "attack_type": "sqli",
  "hash_dim": 262144,
  "ngram_min": 3,
  "ngram_max": 5,
  "dtype": "float32-le",
  "bias": -1.7345,
  "weights_file": "weights.bin",
  "weights_sha256": "sha256:...",
  "model_version": "sgd-global-20260304.1",
  "trained_at": "2026-03-04T02:00:00Z",
  "parent_version": "sgd-global-20260303.3",
  "normalization_profile": "norm-v1"
}
```

#### 9.8.4 Lua scorer 加载方式

第一版运行时固定为 `lua_ffi` scorer，加载时机固定为：

- `init_worker_by_lua*`

执行步骤固定如下：

1. 读取 `manifest.json`
2. 校验 `format`、`attack_type`、`hash_dim`、`dtype`
3. 校验：
   - `manifest.normalization_profile == waf.normalization.active_profile`
4. 读取 `weights.bin`
5. 校验 `weights_sha256`
6. 用 `LuaJIT FFI` 建立连续内存视图
7. 在 worker 内缓存：
   - `bias`
   - `hash_dim`
   - `ngram_range`
   - `weights_ptr`
   - `model_version`
   - `normalization_profile`

明确禁止：

- 每个请求读取模型文件
- 每个请求解析 `manifest.json`
- 把权重大对象放进 `Lua table`

设计原因如下：

- Lua table 内存膨胀明显
- 连续内存视图更适合线性打分
- 这种加载方式与未来 `C + mmap` 更接近

#### 9.8.5 切换、回退与失败处理

激活新版本的流程固定为：

1. `Java` 训练程序产出新版本目录
2. 生成新的 `manifest.json` 和 `weights.bin`
3. 训练程序生成候选版版本记录
4. 自动门禁通过后更新 `current` 版本指针或软链接
5. 执行 `nginx reload`
6. 新 worker 在 `init_worker` 加载新模型
7. 旧 worker 保持旧模型直到优雅退出

回退流程固定为：

1. 将 `current` 指针恢复到上一稳定版
2. 执行 `nginx reload`
3. 新 worker 重新加载旧模型
4. 不做运行时热替换

加载失败时的处理固定为：

- manifest 校验失败：
  - 新模型不生效
  - 保持当前稳定版继续服务
- `normalization_profile` 不一致：
  - 新模型不生效
  - `sgd_model_state = disabled`
  - 写 `alert_log`
- weights 校验失败：
  - 新模型不生效
  - 保持当前稳定版继续服务
- worker 初始化加载失败：
  - 该 worker 不激活新模型
  - 必须记录错误日志
  - `SGD` 插件可降级为 `disabled`
  - 不得影响 `libinjection`、精确豁免匹配和基础规则继续运行

#### 9.8.6 性能门槛与升级条件

第一版 `lua_ffi` scorer 必须满足：

- 单字段 `SGD` 打分常规耗时 `p99 < 200us`
- 单请求总 `SGD` 打分贡献 `p99 < 1ms`
- 两个模型常驻额外内存总量目标 `< 8MB/worker`
- 在目标 QPS 下无明显 Lua GC 抖动放大

满足任一条件时，才进入 `C + mmap` 升级评估：

- `SGD` scorer 在生产压测中导致总检测链 `p99` 持续超预算
- worker RSS 增长超出目标且确认主要来自 Lua scorer
- Lua GC 抖动导致请求尾延迟不可接受
- scorer 计算热点在 CPU profile 中占比持续过高

升级原则固定如下：

- 升级只替换 scorer 实现
- 不改变：
  - 训练产物格式
  - 版本清单结构
  - 发布和回退流程
  - 策略聚合语义

### 9.9 训练方式

- 通过 `cron` 或 `systemd timer` 夜间拉起
- 读取本机样本文件
- 训练完成后退出
- 不引入常驻训练服务

### 9.10 模型上线规则

发布状态机固定为：

- `candidate -> shadow_observe -> stable`

默认采用指标门禁自动晋级：

- 离线门禁达标后进入 `shadow_observe`
- 影子期线上门禁达标后自动晋级 `stable`
- 任一门禁失败时：
  - 保持旧 `stable`
  - 自动告警
  - 不允许绕过门禁替换线上版本

仅在以下情况触发人工介入：

- 门禁失败且连续异常
- 指标出现显著退化
- 资源指标异常（超时、内存、尾延迟恶化）

### 9.11 冷启动与最低上线门槛

`SGD` 在样本量不足阶段的评分默认不可信，必须定义冷启动状态。

第一版固定模型状态如下：

- `cold_start`
- `candidate`
- `shadow_observe`
- `stable`
- `disabled`

状态语义固定如下：

- `cold_start`
  - 允许计算原始分数
  - 允许记录日志和样本
  - `sgd_decision_weight = 0`
  - 不允许参与任何真实决策
- `candidate`
  - 已满足最低样本量门槛
  - 已完成离线评估
  - 未通过时保持候选，不参与线上决策
  - `sgd_decision_weight = 0`
- `shadow_observe`
  - 已通过离线门禁
  - 在线影子期观察
  - `sgd_decision_weight = 0`
- `stable`
  - 已通过离线和影子门禁
  - 自动晋级为稳定版本
  - 允许作为辅助评分参与策略聚合
- `disabled`
  - 模型缺失、校验失败或被手动关闭
  - 不计算、不参与、不记录分数

最低样本量门槛固定如下：

- 每个攻击类型模型至少需要：
  - `positive_samples >= 1000`
  - `negative_samples >= 5000`
  - `hard_negative_samples >= 1000`

最低离线评估门槛固定如下：

- `precision_at_assist_threshold >= 0.95`
- 干净验证集 `false_positive_rate <= 0.001`
- `hard_negative` 验证集 `false_positive_rate <= 0.01`

只有同时满足以下条件，模型才允许从 `candidate` 升为 `shadow_observe`：

- 达到最低样本量门槛
- 达到最低离线评估门槛
- 自动离线门禁通过

从 `shadow_observe` 升为 `stable` 的条件固定为：

- 影子观察窗口 `>= 72h`
- `predicted_high` 抽检误报率不超过阈值
- 相比上一稳定版无显著回归
- timeout/资源指标未恶化

未满足任一条件时：

- `SGD` 权重强制为 `0`
- 仅记录 `sgd_score_raw`
- 不允许影响 `decision_candidate`

设计意图如下：

- 冷启动阶段避免把不稳定模型引入生产决策
- 把“模型可用”定义成显式门槛，而不是模糊判断
- 保持模型引入过程可审计、可回退

## 10. 版本管理、发布与回退

### 10.1 版本对象

- `base_model_version`
- `policy_version`
- `ruleset_version`
- `exemptions_generation`

语义固定如下：

- `policy_version`：
  - 正式发布版本号
  - 包含：
    - 运行模式配置
    - 高误报字段保护范围
    - 可选接口约束开关
    - 基线豁免快照标识（可选）
- `exemptions_generation`：
  - 运行时热更新代次
  - 对应当前生效的 `exemptions.compiled.json`
  - 由热更新通道推进，不要求走正式发布流程

明确规则：

- 日常误报快速豁免更新：
  - 只推进 `exemptions_generation`
  - 不变更 `policy_version`
- 周期性豁免归档（例如每周）：
  - 将已稳定的热更豁免并入基线策略
  - 走正式发布流程
  - 变更 `policy_version`

### 10.2 发布流程

发布流程固定拆分为两条通道。

#### 10.2.1 热更新通道（误报快速处理）

1. 在候选列表中批量确认 `auto_suggested` 或人工确认误报
2. 更新 `exemptions.yaml`
3. 执行编译并校验，生成 `exemptions.compiled.json`
4. 原子替换运行时 `compiled.json`
5. worker 自动热加载
6. 仅更新 `exemptions_generation`

#### 10.2.2 正式发布通道（模型/规则/策略）

1. 夜间训练生成 `candidate`
2. 生成评估报告
3. 自动离线门禁评估
4. 进入 `shadow_observe` 影子期
5. 自动影子门禁评估
6. 门禁通过后自动发布为 `stable`
7. 更新：
   - `base_model_version`
   - `policy_version`
   - `ruleset_version`
8. 必要时回退旧版本

### 10.3 发布原则

- 不允许绕过门禁直接替换线上版本
- 每次发布都必须具备评估结果
- 每次发布都必须保留回滚目标
- 默认按指标门禁自动晋级
- 人工介入只在门禁异常时触发
- 热更新与正式发布解耦：
  - `exemptions_generation` 可高频变化
  - `policy_version` 低频变化并可审计

### 10.4 回退原则

- 必须支持快速回退
- 回退不依赖重新训练
- 热更新回退：
  - 回退到上一代 `exemptions.compiled.json`
  - 回退后更新 `exemptions_generation`
  - 不需要 `nginx reload`
- 正式发布回退：
  - 回退同时恢复：
    - 模型版本
    - 策略版本
    - 规则版本

### 10.5 上线策略（人工最小化）

第一版上线建议固定为四阶段：

1. 启用 `shadow` 模式 + 自动候选生成，`auto_apply=false`
2. 运行 `1-2 周`，验证候选质量与反投毒指标
3. 启用 `first_seen` 人工复核，历史模式自动处理
4. 启用 `SGD` 自动晋级门禁（`candidate -> shadow_observe -> stable`）

阶段目标：

- 阶段 1：把人工工作从“逐条事件”转换为“批量候选确认”
- 阶段 2：验证模式记忆库稳定性和误报收敛能力
- 阶段 3：将人工复核收敛到“首次出现模式”
- 阶段 4：将模型发布从“人工审批”收敛为“指标门禁”

## 11. 性能、内存与平台约束

### 11.1 性能指标

常规请求新增检测目标：

- `p95 < 2ms`
- `p99 < 5ms`
- 硬上限 `< 10ms`

### 11.2 内存指标

单请求额外检测内存：

- 常规 `< 512KB`
- 大文本 `< 2MB`
- 硬上限 `< 32MB`

单 worker 额外常驻内存目标：

- `< 24MB`

### 11.3 平台支持

- `Linux x86_64`
- `Linux arm64`

### 11.4 实现要求

- 核心运行时使用可移植 `C`
- 采集和策略编排尽量使用 `Lua`
- 训练使用 `Java`
- 不依赖仅限 `x86` 的专用实现

## 12. 配置接口设计

### 12.1 `waf` 主配置结构

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
  rule_engine:
    enabled: true
    regex_jit: true
    max_rules: 40
    max_regex_rules: 15
  exemptions:
    enabled: true
    authoring_source: "/opt/waf/policy/exemptions.yaml"
    runtime_source: "/opt/waf/policy/exemptions.compiled.json"
    hot_reload: true
    leader_poll_interval_seconds: 5
    worker_apply_interval_seconds: 1
    shared_dict: "waf_control"
    require_exact_scope: true
    allow_detector_scope_exemption: true
    detector_scope_default_ttl_days: 30
    allow_route_wildcard: false
    allow_detector_wildcard: false
    allow_field_only_exemption: false
  heuristic_signals:
    enabled: true
    max_field_length_signal: true
    charset_anomaly_signal: true
    control_char_signal: true
    delimiter_density_signal: true
    keyword_density_signal: true
    encoding_depth_signal: true
    repeated_param_signal: true
  operations:
    review_mode: pattern_first_seen
    shadow_auto_suggest:
      enabled: true
      window_days: 7
      min_hits: 200
      min_2xx_ratio: 0.995
      min_unique_ip: 20
      min_ip_entropy: 2.5
      max_single_ip_ratio: 0.2
      scanner_ratio_threshold: 0.05
      auto_apply: false
    high_queue:
      only_first_seen: true
    pattern_memory:
      enabled: true
      states:
        - unknown
        - benign_confirmed
        - attack_confirmed
    sgd_release:
      auto_promote: true
      shadow_observe_hours: 72
      promote_on_metrics: true
      require_manual_on_anomaly: true
  learning:
    enabled: false
    collect_window: "09:00-23:00"
    train_window: "01:00-04:00"
    trainer_command: "/opt/waf/bin/java-train-candidate"
    allow_worker_training: false
    clean_sample_rate: 0.01
    weak_signal_allow_sample_rate: 1.0
    hard_negative_sample_rate: 1.0
    per_route_field_clean_cap_per_hour: 1000
    per_route_field_clean_floor_per_hour: 20
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
    multipart_filename_max_bytes: 512
    inspect_multipart_filename: true
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
    validate_checksum: true
    sqli_manifest_path: "/opt/waf/models/sqli/current.manifest.json"
    xss_manifest_path: "/opt/waf/models/xss/current.manifest.json"
    sqli_weights_path: "/opt/waf/models/sqli/current.weights.bin"
    xss_weights_path: "/opt/waf/models/xss/current.weights.bin"
  optional_constraints:
    enabled: false
    source: "/opt/waf/policy/constraints.yaml"
  logging:
    runtime_alert_log_enabled: true
    runtime_low_alert_log_enabled: false
    runtime_trace_log_enabled: false
    runtime_trace_sample_rate: 0.001
    sample_log_rotate: daily
    sample_log_compress: true
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

### 12.2 `capture` 子配置结构

```yaml
capture:
  headers_whitelist:
    - content-type
    - content-length
    - user-agent
    - referer
  query:
    enabled: true
    max_query_args: 64
    max_query_bytes: 8192
  body:
    enabled: true
    require_content_length: true
    max_parse_bytes: 131072
    hard_max_parse_bytes: 1048576
    allowed_content_types:
      - application/json
      - application/x-www-form-urlencoded
      - text/plain
    allow_temp_file_readback: true
    skip_if_chunked: true
  json:
    max_fields: 128
    max_depth: 8
    max_string_field_bytes: 4096
  form:
    max_fields: 128
    max_field_bytes: 4096
  multipart:
    inspect_metadata: true
    inspect_text_parts: true
    inspect_filename: true
    filename_max_bytes: 512
    inspect_file_content: false
```

### 12.3 `learning` 子配置结构

```yaml
learning:
  enabled: false
  collect_window: "09:00-23:00"
  train_window: "01:00-04:00"
  sample_log_path: "/var/log/waf/samples"
  trainer_command: "/opt/waf/bin/java-train-candidate"
  allow_worker_training: false
  clean_sample_rate: 0.01
  weak_signal_allow_sample_rate: 1.0
  hard_negative_sample_rate: 1.0
  per_route_field_clean_cap_per_hour: 1000
  per_route_field_clean_floor_per_hour: 20
```

### 12.4 `model_registry` 版本结构

```json
{
  "base_model_version": "sgd-global-20260304.1",
  "policy_version": "waf-policy-20260304.1",
  "ruleset_version": "waf-rules-20260304.1",
  "exemptions_generation": 1284,
  "exemptions_sha256": "sha256:...",
  "dataset_snapshot": "ds-20260304-a1",
  "scorer_backend": "lua_ffi",
  "active_normalization_profile": "norm-v1",
  "weight_format": "manifest+weights-bin-f32-le-v1",
  "sqli_manifest_path": "/opt/waf/models/sqli/current.manifest.json",
  "xss_manifest_path": "/opt/waf/models/xss/current.manifest.json",
  "sqli_weights_path": "/opt/waf/models/sqli/current.weights.bin",
  "xss_weights_path": "/opt/waf/models/xss/current.weights.bin",
  "trained_at": "2026-03-04T02:00:00Z",
  "compatible_arch": ["linux/amd64", "linux/arm64"],
  "parent_version": "sgd-global-20260303.3",
  "status": "candidate"
}
```

### 12.5 `lua_shared_dict waf_control` 元数据键

运行时固定使用：

- `lua_shared_dict waf_control`

该 shared dict 只允许保存豁免热更新元数据，不允许存放完整豁免表。

至少包含以下键：

- `exemptions.target_generation`
- `exemptions.target_sha256`
- `exemptions.target_mtime`
- `exemptions.target_size`
- `exemptions.last_publish_status`
- `exemptions.last_error`
- `exemptions.last_publish_ts`

### 12.6 运营自动化类型

为支持人工最小化运营，第一版新增以下类型定义：

- `candidate_status`
  - `auto_suggested`
  - `approved`
  - `rejected`
  - `expired`
- `candidate_reason`
  - `high_freq_benign_pattern`
  - `first_seen_resolved_benign`
  - `manual_override`
- `pattern_state`
  - `unknown`
  - `benign_confirmed`
  - `attack_confirmed`

## 13. 日志与样本格式设计

### 13.1 运行时检测日志 JSON 结构

运行时日志除常规请求元数据外，必须额外包含以下策略字段：

- `route_key`
- `field_name`
- `json_path`
- `detector`
- `detector_signature`
- `exemption_applied`
- `exemption_id`
- `exemption_match_scope`
- `exemption_match_key`
- `scope_relaxation_applied`
- `source_event_ids_digest`
- `policy_decision_basis`
- `weak_signal_tags`
- `review_queue`
- `pattern_key`
- `pattern_state`
- `first_seen_pattern`
- `candidate_status`
- `candidate_reason`
- `normalization_profile`
- `model_sqli_input`
- `model_xss_input`
- `model_input_truncated`
- `timeout_stage`
- `hard_timeout_ms`
- `detector_stage_reached`
- `budget_exhausted`
- `elapsed_ms`
- `exemptions_generation`

```json
{
  "ts": "2026-03-04T10:10:10Z",
  "request_id": "req-123",
  "mode": "shadow",
  "decision_candidate": "block",
  "enforced_action": "allow",
  "threat_classification": "suspected_attack",
  "alert_level": "high",
  "uri": "/api/search",
  "route_key": "/api/search",
  "method": "POST",
  "content_type": "application/json",
  "content_length": 128,
  "field_name": "keyword",
  "json_path": "$.keyword",
  "detector": "libinjection_sqli",
  "detector_signature": "sqli_fingerprint_xxx",
  "exemption_match_scope": "",
  "exemption_match_key": "",
  "scope_relaxation_applied": false,
  "source_event_ids_digest": "",
  "policy_decision_basis": "parser_hit_shadow",
  "exemption_applied": false,
  "exemption_id": "",
  "review_queue": "first_seen_only",
  "pattern_key": "POST|/api/search|json|keyword|libinjection_sqli|sqli_fingerprint_xxx",
  "pattern_state": "unknown",
  "first_seen_pattern": true,
  "candidate_status": "auto_suggested",
  "candidate_reason": "high_freq_benign_pattern",
  "weak_signal_tags": ["keyword_density", "encoding_depth"],
  "normalization_profile": "norm-v1",
  "sgd_backend": "lua_ffi",
  "sgd_model_state": "stable",
  "sgd_score_raw": 0.94,
  "sgd_score_used": 0.94,
  "sgd_decision_weight": 1.0,
  "model_version": "sgd-global-20260304.1",
  "raw_value": "%2527%20or%201=1--",
  "normalized_sqli_value": "' or 1=1--",
  "normalized_xss_value": "%27 or 1=1--",
  "model_sqli_input": "' or 1=1--",
  "model_xss_input": "%27 or 1=1--",
  "model_input_truncated": false,
  "normalization_steps": ["json_extract", "url_decode:2", "html_entity_decode:0"],
  "url_decode_passes": 2,
  "html_entity_decode_passes": 0,
  "raw_value_truncated": false,
  "normalized_value_truncated": false,
  "plugin_signals": [
    {"plugin": "libinjection_sqli", "matched": true, "confidence": 1.0, "fingerprint": "sqli_fingerprint_xxx"},
    {"plugin": "rule_engine", "matched": true, "confidence": 0.72, "rule_ids": ["sqli_comment_001"]},
    {"plugin": "sgd_sqli", "matched": true, "confidence": 0.94}
  ],
  "final_action": "log",
  "timeout_stage": "",
  "hard_timeout_ms": 10,
  "detector_stage_reached": "sgd_sqli",
  "budget_exhausted": false,
  "elapsed_ms": 1.7,
  "body_inspected": true,
  "body_skip_reason": "",
  "base_model_version": "sgd-global-20260304.1",
  "policy_version": "waf-policy-20260304.1",
  "exemptions_generation": 1284
}
```

### 13.2 样本采集日志 JSON 结构

样本日志必须能够区分：

- 来自高置信 parser 命中
- 来自弱信号放行
- 来自普通正常样本采样
- 是否命中过豁免策略

```json
{
  "ts": "2026-03-04T10:10:10Z",
  "request_id": "req-123",
  "alert_level": "low",
  "uri": "/api/search",
  "route_key": "/api/search",
  "method": "POST",
  "content_type": "application/json",
  "content_length": 128,
  "field_name": "keyword",
  "json_path": "$.keyword",
  "detector": "sgd_sqli",
  "detector_signature": "",
  "exemption_applied": false,
  "exemption_id": "",
  "exemption_match_scope": "",
  "exemption_match_key": "",
  "scope_relaxation_applied": false,
  "source_event_ids_digest": "",
  "pattern_key": "POST|/api/search|json|keyword|sgd_sqli|",
  "pattern_state": "unknown",
  "first_seen_pattern": false,
  "candidate_status": "",
  "candidate_reason": "",
  "weak_signal_tags": ["keyword_density"],
  "normalization_profile": "norm-v1",
  "sgd_backend": "lua_ffi",
  "sgd_model_state": "cold_start",
  "sgd_score_raw": 0.98,
  "sgd_score_used": 0.0,
  "sgd_decision_weight": 0,
  "model_version": "sgd-global-20260304.1",
  "raw_value": "%2527%20or%201=1--",
  "normalized_sqli_value": "' or 1=1--",
  "normalized_xss_value": "%27 or 1=1--",
  "model_sqli_input": "' or 1=1--",
  "model_xss_input": "%27 or 1=1--",
  "model_input_truncated": false,
  "normalization_steps": ["json_extract", "url_decode:2", "html_entity_decode:0"],
  "url_decode_passes": 2,
  "html_entity_decode_passes": 0,
  "timeout_stage": "",
  "hard_timeout_ms": 10,
  "detector_stage_reached": "sgd_sqli",
  "budget_exhausted": false,
  "elapsed_ms": 1.7,
  "body_inspected": true,
  "body_skip_reason": "",
  "sample_reason": "weak_signal_allow_candidate",
  "base_model_version": "sgd-global-20260304.1",
  "policy_version": "waf-policy-20260304.1",
  "exemptions_generation": 1284
}
```

### 13.3 样本日志落盘方式

- 样本由 `Lua` 结构化
- 落盘通过 NGINX 日志链路完成
- 不在热路径用 Lua 高频直接写文件
- 文件格式建议采用 `NDJSON`

### 13.4 日志分流与磁盘控制

第一版不能把“所有检测结果”都写成同一种运行时日志，必须区分以下三类日志：

- `alert_log`
  - 记录 `alert_level != none` 的事件
  - 默认开启
  - 面向运营和安全复核
- `trace_log`
  - 记录完整决策轨迹
  - 默认关闭
  - 仅在 `debug`、专项压测或短时间影子观察时开启
- `sample_log`
  - 面向训练样本积累
  - 按采样率写入

默认规则如下：

- 普通放行请求不写 `alert_log`
- `trace_log` 默认 `disabled`
- `sample_log` 使用独立采样率和配额控制

为控制日志量和磁盘压力，必须增加以下约束：

- `alert_log` 只记录：
  - `critical`
  - `high`
  - 可选 `low`
- `trace_log` 必须支持：
  - 总开关
  - 采样率
  - 时间窗口
  - 路由白名单
- `sample_log` 必须支持：
  - 采样率
  - 按路由/字段配额
  - 按天轮转
  - 压缩

默认配置建议如下：

- `runtime_alert_log_enabled = true`
- `runtime_trace_log_enabled = false`
- `runtime_trace_sample_rate = 0.001`
- `runtime_low_alert_log_enabled = false`
- `sample_log_rotate = daily`
- `sample_log_compress = true`

设计意图如下：

- 让运营看到的是可复核的告警流，而不是全量噪音
- 防止高流量场景下日志把磁盘迅速打满
- 把全量 trace 留给短时排障，而不是长期默认行为

### 13.5 指标与运行告警

必须新增以下指标：

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

必须新增以下运行告警：

- 豁免热更新连续失败
- 任一 worker 落后于最新豁免 generation 超过 `30s`
- `timeout_fail_open` 比例异常升高
- `normalization_profile` mismatch
- `detector_field` 豁免数量异常增长
- `first_seen` 模式数量异常飙升
- `auto_suggested` 候选通过率异常下降
- `SGD` 自动晋级连续失败

## 14. 安全边界与已知限制

### 14.1 已知边界

- 第一版不扫描上传文件内容
- 第一版不解析无 `Content-Length` 的 body
- 大于阈值的 body 不进入深度解析
- 第一版不默认依赖业务方提供接口契约
- `SGD` 不替代应用层输入校验和输出编码
- 对富文本、模板、代码片段类字段必须谨慎处理

默认高误报字段类型包括：

- 评论内容
- 搜索词
- 富文本
- Markdown
- 模板片段
- 代码片段

对这些字段：

- 第一阶段优先走 `shadow` 模式聚类和自动候选
- 更依赖精确豁免，而不是零豁免状态下直接阻断

### 14.2 覆盖范围边界

该方案重点拦截：

- 典型 `SQLi`
- 典型 `XSS`
- 中等复杂度绕过变体

该方案不承诺覆盖：

- 所有业务上下文型攻击
- 所有存储型/二阶攻击
- 所有大包和文件内容攻击

## 15. 测试与验收标准

### 15.1 功能测试

- SQLi 典型 payload
- SQLi 编码绕过
- SQLi 注释绕过
- SQLi 大小写绕过
- SQLi 双重 URL 编码绕过
- `libinjection` 已知薄弱区间专项测试
- XSS 标签型 payload
- XSS 属性型 payload
- XSS 协议型 payload
- XSS 编码变体
- XSS HTML entity 变体
- `query`
- `form`
- `JSON`
- `header`
- `multipart filename`
- `Lua scorer` 正确加载 `manifest.json + weights.bin`
- `sqli` 与 `xss` 两模型分别可独立加载
- 冷启动状态下 `sgd_score_raw` 存在但不参与决策
- `current` 指针切换后 `nginx reload` 可加载新版本
- 回退旧版本后 scorer 恢复正常
- `libinjection` 命中且未豁免时：
  - `shadow` 只记日志
  - `assist` 只告警不阻断
  - `selective_enforce` 可阻断
- `shadow` 自动候选生成：
  - 满足阈值条件生成 `auto_suggested`
  - 不满足任一条件不生成候选
- `libinjection` 命中且已豁免时：
  - 所有模式都放行但保留告警与审计日志
- `high` 告警仅首次出现模式进入人工复核队列
- 历史 `benign_confirmed` 模式自动沿用放行/豁免策略
- 历史 `attack_confirmed` 模式在 `selective_enforce` 下自动进入阻断候选
- `hard_timeout_ms` 触发时：
  - 强制放行
  - 写 `high alert`
  - `policy_decision_basis = timeout_fail_open`
- 日常误报豁免热更新时：
  - `exemptions_generation` 递增
  - `policy_version` 保持不变
- 周期性豁免归档发布时：
  - `policy_version` 递增

### 15.2 误报测试

- 含 SQL 关键字的正常搜索词
- 带引号的人名
- 富文本 HTML
- Markdown
- 模板语法
- 代码片段
- 同一路由不同字段不会错误复用豁免
- 同字段不同检测器不会错误复用豁免
- 同字段不同 fingerprint 不会错误复用豁免
- 粗粒度 route 豁免配置被拒绝加载
- `detector_field` 只对显式批准字段生效
- `detector_field` 到期后自动失效
- 单 IP 高频命中不会触发 `auto_suggested`
- 高扫描器占比模式不会触发 `auto_suggested`

### 15.3 性能测试

- `amd64`
- `arm64`
- 小 body
- temp-file body
- `JSON/form/text` 场景
- `lua_ffi` scorer 单字段耗时基准
- 小请求、中请求、多字段请求下的 scorer 总耗时
- 高频请求下 Lua GC 行为
- 豁免热更新传播时间 `<= 10s`

### 15.4 一致性测试

- Java 导出权重与 Lua scorer 计算结果一致
- 相同输入在同版本 scorer 下结果稳定
- manifest 中 `hash_dim/ngram/bias` 与 scorer 使用值一致
- weights 校验失败时模型不生效
- 同一 `manifest.json + weights.bin` 格式必须可被未来 C scorer 读取
- 同一 corpus 在 Java 和 Lua 下生成完全一致的：
  - `normalized_sqli_value`
  - `normalized_xss_value`
  - `model_sqli_input`
  - `model_xss_input`
- `manifest.normalization_profile != runtime.active_profile` 时模型必须被禁用
- `SGD` 自动晋级门禁：
  - 离线门禁通过后进入 `shadow_observe`
  - 影子门禁通过后自动晋级 `stable`
  - 指标退化时自动阻断晋级并保留旧 `stable`

### 15.5 验收标准

- 不依赖 `NAXSI` 阻断
- `SGD` 不单独阻断
- body 解析满足白名单和阈值约束
- 冷启动阶段 `SGD` 决策权重必须为 `0`
- 第一版生产 scorer 后端固定为 `lua_ffi`
- 第一版不依赖业务方提供接口契约
- 第一版必须支持 `shadow -> assist -> selective_enforce`
- `selective_enforce` 只对未豁免的高置信 parser 命中实施真实阻断
- 人工复核默认只处理首次出现模式
- `shadow` 期支持模式聚类自动候选并支持批量确认
- 豁免更新不需要 `nginx reload`
- 豁免热更新失败不影响旧版本继续服务
- timeout 固定 `fail_open`
- `norm-v1` 的 Java/Lua 一致性测试必须通过
- 满足性能与内存硬指标
- 支持候选版、稳定版、回退版切换

## 16. 后续扩展预留

### 16.1 扩展能力

架构预留后续能力扩展位，包括但不限于：

- `SSRF`
- `命令注入`
- `路径穿越`
- `上传策略`
- `Bot` 信号

### 16.2 扩展原则

- 所有能力仍通过统一插件接口接入
- 只有轻量同步能力可进入热路径
- 重型能力必须旁路化或异步化

## 17. 默认参数与关键假设

- 第一版仅做 `SQLi + XSS`
- 采集尽量用 `OpenResty + Lua`
- 训练由 `Java` 夜间批处理程序完成
- 不新增常驻训练服务
- 训练数据通过本机文件链路传递
- 不使用 `NAXSI` 作为生产阻断核心
- 不使用大型负向规则库
- 反向代理默认不知道业务字段语义
- 第一版不依赖业务方提供接口契约
- 第一版误报治理主机制是“精确豁免”，不是“正向约束”
- 第一版必须先经过 `shadow` 期积累误报模式与候选豁免
- `assist` 主要用于收敛误报与首次模式复核，不作为大面积阻断阶段
- `selective_enforce` 只对未豁免的高置信 parser 命中实施真实阻断
- 弱启发式和 `SGD` 默认不单独阻断
- 豁免是第一版唯一允许高频热更新的策略工件
- 规则、模型和主配置仍通过发布流程和 `nginx reload`
- 日常误报豁免热更新只推进 `exemptions_generation`，不变更 `policy_version`
- 周期性豁免归档走正式发布流程并更新 `policy_version`
- 豁免热更新默认：
  - leader 轮询 `5s`
  - worker 应用 `1s`
- `detector_field` 默认 TTL 为 `30 days`
- body 默认解析上限 `128KB`
- body 硬上限 `1MB`
- 普通正常样本默认采样率 `1%`
- 弱信号放行样本默认采样率 `100%`
- `multipart.filename` 进入完整检测链
- 第一版 scorer 后端固定为 `lua_ffi`
- 模型文件格式固定为 `manifest.json + weights.bin`
- `weights.bin` 为 `float32 little-endian` flat binary
- `bias` 固定放在 `manifest.json`
- 阈值不放在模型文件中，仍放在策略配置中
- 第一版激活的 `normalization_profile` 固定为 `norm-v1`
- `model_feature_max_bytes = 2048`
- `hard_timeout_ms = 10`
- `timeout_policy = fail_open`
- `high` 告警默认只对首次出现模式触发人工复核
- `shadow` 自动候选默认开启，但自动生效默认关闭（仅 `auto_suggested`）
- `SGD` 发布默认启用指标门禁自动晋级，异常才人工介入
- 性能不达标时才进入 `C + mmap` 升级评估
- 平台为 `Linux x86_64 + arm64`

## 附录 A：策略与豁免 YAML 结构

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

optional_constraints:
  enabled: false
  rules:
    - id: route_user_id_int
      type: positive_constraint
      route: "/api/user/update"
      field_name: "userId"
      constraint: integer
      action: block
```

## 附录 B：测试用例与场景

### B.1 请求采集与解析

- 小 JSON 正常解析
- 小 form 正常解析
- temp-file body 读回解析
- 超阈值 body 跳过
- multipart 只读文本字段
- multipart filename 进入检测链
- `%2527` 按两次 URL decode 展开
- `&lt;script&gt;` 只在 XSS 视图做 entity decode
- `JSON/text/plain/header` 默认不做 URL decode
- `Java` 与 `Lua` 在 `norm-v1` 下生成完全一致的：
  - `normalized_sqli_value`
  - `normalized_xss_value`
  - `model_sqli_input`
  - `model_xss_input`

### B.2 检测与阻断

- 高置信 SQLi 阻断
- 高置信 XSS 阻断
- `libinjection` 命中且已豁免时放行并审计
- `detector_field` 豁免对同字段不同 fingerprint 生效
- 弱规则 + 高模型分只升权
- 富文本字段误报控制
- `libinjection` 未命中但弱规则 + 高模型分触发 `high` 告警
- `libinjection` 已知绕过变体专项测试：
  - MySQL 版本注释变体
  - 关键字注释拆分变体
  - 双重 URL 编码变体
  - 宽字节/编码边界变体

### B.3 版本切换

- 候选版生成
- 影子观察
- 稳定版切换
- 自动门禁晋级：
  - `candidate -> shadow_observe -> stable`
- 回退旧版本
- 模型文件损坏时保持旧版本继续服务
- `manifest.json + weights.bin` 切换后 Lua scorer 正常加载
- `manifest.normalization_profile != active_profile` 时模型被禁用

### B.4 模式语义

- `shadow` 模式下 `decision_candidate=block` 但 `enforced_action=allow`
- `assist` 模式下未豁免的高置信解析器命中只告警不阻断
- `selective_enforce` 模式下仅未豁免的高置信解析器命中允许进入真实阻断
- `selective_enforce` 模式下弱规则组合默认仍不阻断

### B.5 豁免热更新与 timeout

- 发布新的 `exemptions.compiled.json` 后无需 `nginx reload` 即生效
- 非法 `compiled.json` 不推进 generation，旧豁免继续服务
- 重复 key 的豁免条目导致热更新失败
- `shadow` 期自动生成 `auto_suggested` 候选
- `high` 告警仅首次出现模式进入人工复核
- 日常误报热更新仅变化 `exemptions_generation`，不变化 `policy_version`
- 周期性归档发布后 `policy_version` 变化并可审计追踪
- `hard_timeout_ms` 在规范化阶段触发时：
  - `fail_open`
  - `policy_decision_basis = timeout_fail_open`
- `hard_timeout_ms` 在 `SGD` 阶段触发时：
  - `fail_open`
  - `alert_level = high`
