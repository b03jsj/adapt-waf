# OpenResty WAF 设计方案

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
- 生产主链固定为：`libinjection + 自有轻量策略引擎 + 正向约束 + SGD辅助评分`
- `SGD` 不允许 `model-only block`
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
- 自有轻量小规则集处理少量绕过和弱信号
- 路由/字段级正向约束负责控制误拦
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
5. 轻量规则检测
6. 正向约束检查
7. `SGD` 辅助评分
8. 策略聚合
9. 动作执行
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

#### 自有轻量策略引擎

- 仅负责少量弱规则与绕过迹象检测
- 不采用大规模规则库
- 优先使用字符串扫描和字符级判断

#### 正向约束

- 基于路由和字段约束合法输入
- 负责降低误拦
- 示例：
  - 指定字段必须为整数
  - 指定字段长度上限固定
  - 指定接口只允许 JSON 且字段集合固定

#### `sgd_sqli`

- 用于 `SQLi` 辅助评分
- 不单独阻断

#### `sgd_xss`

- 用于 `XSS` 辅助评分
- 不单独阻断

### 6.2 阻断规则

- 高置信解析器命中可直接进入阻断候选
- `SGD` 不允许 `model-only block`
- 弱规则只有在和其它信号组合时才允许升权
- 富文本、模板、代码片段类字段默认不允许仅凭弱规则或模型高分直接阻断

### 6.3 策略聚合规则

建议的聚合逻辑如下：

- `libinjection` 命中：
  - 高优先级阻断候选
- 正向约束明确违规：
  - 高优先级阻断候选
- 弱规则命中 + 高模型分：
  - 中高优先级阻断候选
- 仅模型高分：
  - 只记录日志，不阻断

### 6.4 运行模式语义

配置项 `mode: shadow | assist | selective_enforce` 必须有严格、不可歧义的运行语义。

#### `shadow`

- 执行完整检测链：
  - 规范化
  - 高置信检测
  - 轻量规则
  - 正向约束
  - `SGD`
  - 策略聚合
- 生成完整的 `decision_candidate`
- 输出完整日志和样本
- 实际执行动作固定为：
  - `allow`
- 该模式下不因本模块的新检测结果阻断请求

用途：

- 上线前观察
- 新模型观察
- 新规则观察
- 误报分析

#### `assist`

- 执行完整检测链
- 默认只对“受保护的高置信信号”实施阻断
- 允许阻断的信号固定为：
  - `libinjection_sqli`
  - `libinjection_xss`
  - 正向约束的明确违规
- 以下信号在 `assist` 模式下只记录，不阻断：
  - 单独弱规则命中
  - 弱规则 + 高模型分
  - 仅模型高分

用途：

- 作为生产默认安全基线
- 先保证明显攻击可拦截
- 同时压低误拦

#### `selective_enforce`

- 执行完整检测链
- 全局仍然阻断“受保护的高置信信号”
- 在此基础上，仅对已批准的路由/字段策略开启增强阻断
- 允许增强阻断的组合固定为：
  - 弱规则 + 高模型分
  - 多弱信号叠加 + 高模型分
  - 特定路由/字段上的高风险弱规则
- 未被显式批准进入增强阻断范围的路由/字段，行为必须退化为 `assist`
- `model-only block` 在该模式下仍然禁止

用途：

- 对低误报、已验证接口逐步加强拦截
- 按路由、字段灰度放量

#### 模式实现要求

- 所有模式都必须输出：
  - `decision_candidate`
  - `enforced_action`
- `shadow` 模式中：
  - `decision_candidate` 可为 `block`
  - 但 `enforced_action` 必须为 `allow`
- `assist` 和 `selective_enforce` 的差异，必须体现在是否允许“弱规则组合”进入真实阻断
- `model-only block` 在任何模式下都必须为 `false`

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
- `text/*`

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
  - 自有轻量规则
  - 正向约束
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
- `text/*`
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
- 对 `JSON/text/header` 默认不做 URL decode，可以降低把本来不会被业务再次解码的内容误判成攻击的风险

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

## 8. 规则与检测能力设计

### 8.1 规则来源

第一版不引入大型外部规则库。规则来源固定为：

- `libinjection`
- 自有固定小规则集
- 路由/字段级正向约束

### 8.2 自有小规则集设计原则

规则重点覆盖：

- URL 编码和双重编码异常
- HTML entity / Unicode escape 混淆
- SQL 注释拆分与空白绕过
- 危险标签和危险协议片段
- 明显异常的连接、拼接和闭合结构

### 8.3 实现优先级

优先使用：

- 普通字符串扫描
- 字符级状态机
- 长度规则
- 字符集规则
- 计数规则

少量必要场景才使用 `Lua regex`。

### 8.4 Lua regex 约束

- `Lua regex` 可用，但只能少量使用
- 必须启用：
  - `pcre_jit on;`
  - `ngx.re.find(..., "jo")` 或等价缓存/JIT策略
- 总 regex 规则数必须受控
- 禁止堆大量泛化 regex
- 禁止对大 body 做多轮全量 regex 扫描

### 8.5 规则规模控制

建议第一版控制在：

- 总规则数 `<= 40`
- 其中 regex 规则数 `<= 15`

### 8.6 规则新增要求

每条新增规则必须具备：

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

`SGD` 的权重加载方案必须明确，第一版固定如下：

- 训练程序由 `Java` 导出版本化二进制模型文件
- 每个模型一个独立文件：
  - `sqli` 模型
  - `xss` 模型
- 每个模型必须配套一个 `manifest`
- 运行时不从 `Lua table`、`JSON` 或文本格式动态加载权重

模型文件格式固定为：

- 文件头
  - `magic`
  - `format_version`
  - `attack_type`
  - `hash_dim`
  - `ngram_range`
  - `bias`
  - `weight_dtype`
  - `weight_count`
  - `checksum`
- 权重区
  - 固定长度 `float32` 权重数组

兼容性约束如下：

- 文件字节序固定为 `little-endian`
- 加载器必须校验：
  - `magic`
  - `format_version`
  - `attack_type`
  - `hash_dim`
  - `checksum`

运行时加载方式固定为：

- 模型文件按版本落盘
- 运行时由 `C` 模块使用只读 `mmap` 加载
- 权重不进入 `Lua table`
- 多个 worker 通过操作系统页缓存共享模型页
- 每个 worker 只持有只读句柄和必要元数据

激活新版本的流程固定为：

1. `Java` 训练程序生成新的版本化模型文件和 `manifest`
2. 训练程序生成候选版版本记录
3. 人工审核通过后更新 `current` 版本指针或软链接
4. 执行 `nginx reload`
5. 新 worker 加载新模型
6. 旧 worker 保持旧模型直到优雅退出

回退流程固定为：

1. 将 `current` 指针恢复到上一稳定版
2. 执行 `nginx reload`
3. 新 worker 重新加载旧模型

加载失败时的处理固定为：

- 新模型校验失败：
  - 不激活
  - 保持当前稳定版继续服务
- 运行时加载失败：
  - 禁止替换当前稳定版
  - 记录错误日志
  - `SGD` 插件可降级为禁用，但不得影响 `libinjection` 和基础规则继续运行

此方案的设计意图如下：

- 避免把权重加载做成 Lua 大对象，减少内存抖动
- 避免运行时热替换带来的不确定状态
- 利用 `mmap` 和页缓存降低多 worker 的重复内存占用
- 保证版本切换和回退行为简单、可验证、可审计

### 9.9 训练方式

- 通过 `cron` 或 `systemd timer` 夜间拉起
- 读取本机样本文件
- 训练完成后退出
- 不引入常驻训练服务

### 9.10 模型上线规则

- 夜间只生成 `candidate`
- 需要人工审核
- 需要影子观察
- 通过后才发布为 `stable`

## 10. 版本管理、发布与回退

### 10.1 版本对象

- `base_model_version`
- `policy_version`
- `ruleset_version`

### 10.2 发布流程

1. 夜间训练生成 `candidate`
2. 生成评估报告
3. 人工审核
4. 影子观察
5. 人工发布为 `stable`
6. 必要时回退旧版本

### 10.3 发布原则

- 不自动替换线上版本
- 每次发布都必须具备评估结果
- 每次发布都必须保留回滚目标

### 10.4 回退原则

- 必须支持快速回退
- 回退不依赖重新训练
- 回退同时恢复：
  - 模型版本
  - 策略版本
  - 规则版本

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
    url_decode_max_passes: 2
    url_decode_surfaces:
      - query
      - form
      - multipart_filename
    html_entity_decode_for_xss: true
    html_entity_decode_max_passes: 2
    html_entity_decode_for_sqli: false
    unicode_normalization: none
    log_value_max_bytes: 512
  rule_engine:
    enabled: true
    regex_jit: true
    max_rules: 40
    max_regex_rules: 15
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
      - text/*
    allow_temp_file_readback: true
    multipart_filename_max_bytes: 512
    inspect_multipart_filename: true
    inspect_multipart_file_content: false
  model:
    allow_model_only_block: false
    load_mode: mmap
    validate_checksum: true
    sqli_manifest_path: "/opt/waf/models/sqli/current.manifest.json"
    xss_manifest_path: "/opt/waf/models/xss/current.manifest.json"
    sqli_model_path: "/opt/waf/models/sqli/current.bin"
    xss_model_path: "/opt/waf/models/xss/current.bin"
  limits:
    target_p95_ms: 2
    target_p99_ms: 5
    hard_timeout_ms: 10
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
      - text/*
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
  "dataset_snapshot": "ds-20260304-a1",
  "weight_format": "sgd-linear-f32-le-v1",
  "sqli_manifest_path": "/opt/waf/models/sqli/current.manifest.json",
  "xss_manifest_path": "/opt/waf/models/xss/current.manifest.json",
  "trained_at": "2026-03-04T02:00:00Z",
  "compatible_arch": ["linux/amd64", "linux/arm64"],
  "parent_version": "sgd-global-20260303.3",
  "status": "candidate"
}
```

## 13. 日志与样本格式设计

### 13.1 运行时检测日志 JSON 结构

```json
{
  "ts": "2026-03-04T10:10:10Z",
  "request_id": "req-123",
  "mode": "shadow",
  "decision_candidate": "block",
  "enforced_action": "allow",
  "uri": "/api/comment",
  "method": "POST",
  "content_type": "application/json",
  "content_length": 4096,
  "field": "content",
  "raw_value": "\"<b>hello</b>\"",
  "normalized_sqli_value": "\"<b>hello</b>\"",
  "normalized_xss_value": "<b>hello</b>",
  "normalization_steps": ["json_extract", "html_entity_decode:0", "url_decode:0"],
  "url_decode_passes": 0,
  "html_entity_decode_passes": 0,
  "raw_value_truncated": false,
  "normalized_value_truncated": false,
  "plugin_signals": [
    {"plugin": "libinjection_xss", "matched": false, "confidence": 0.0},
    {"plugin": "rule_engine", "matched": true, "confidence": 0.72, "rule_ids": ["xss_proto_001"]},
    {"plugin": "sgd_xss", "matched": true, "confidence": 0.98}
  ],
  "final_action": "log",
  "body_inspected": true,
  "body_skip_reason": "",
  "base_model_version": "sgd-global-20260304.1",
  "policy_version": "waf-policy-20260304.1"
}
```

### 13.2 样本采集日志 JSON 结构

```json
{
  "ts": "2026-03-04T10:10:10Z",
  "request_id": "req-123",
  "uri": "/api/comment",
  "method": "POST",
  "content_type": "application/json",
  "content_length": 4096,
  "field": "content",
  "raw_value": "\"<b>hello</b>\"",
  "normalized_sqli_value": "\"<b>hello</b>\"",
  "normalized_xss_value": "<b>hello</b>",
  "normalization_steps": ["json_extract", "html_entity_decode:0", "url_decode:0"],
  "url_decode_passes": 0,
  "html_entity_decode_passes": 0,
  "body_inspected": true,
  "body_skip_reason": "",
  "sample_reason": "clean_candidate",
  "base_model_version": "sgd-global-20260304.1",
  "policy_version": "waf-policy-20260304.1"
}
```

### 13.3 样本日志落盘方式

- 样本由 `Lua` 结构化
- 落盘通过 NGINX 日志链路完成
- 不在热路径用 Lua 高频直接写文件
- 文件格式建议采用 `NDJSON`

## 14. 安全边界与已知限制

### 14.1 已知边界

- 第一版不扫描上传文件内容
- 第一版不解析无 `Content-Length` 的 body
- 大于阈值的 body 不进入深度解析
- `SGD` 不替代应用层输入校验和输出编码
- 对富文本、模板、代码片段类字段必须谨慎处理

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

### 15.2 误报测试

- 含 SQL 关键字的正常搜索词
- 带引号的人名
- 富文本 HTML
- Markdown
- 模板语法
- 代码片段

### 15.3 性能测试

- `amd64`
- `arm64`
- 小 body
- temp-file body
- `JSON/form/text` 场景

### 15.4 验收标准

- 不依赖 `NAXSI` 阻断
- `SGD` 不单独阻断
- body 解析满足白名单和阈值约束
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
- body 默认解析上限 `128KB`
- body 硬上限 `1MB`
- 普通正常样本默认采样率 `1%`
- 弱信号放行样本默认采样率 `100%`
- `multipart.filename` 进入完整检测链
- `SGD` 权重由 `Java` 导出二进制模型，运行时通过 `C + mmap` 只读加载
- 平台为 `Linux x86_64 + arm64`

## 附录 A：规则定义 YAML 结构

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

  - id: route_user_id_int
    type: positive_constraint
    route: "/api/user/update"
    field: "userId"
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
- `JSON/text/header` 默认不做 URL decode

### B.2 检测与阻断

- 高置信 SQLi 阻断
- 高置信 XSS 阻断
- 弱规则 + 高模型分只升权
- 富文本字段误报控制

### B.3 版本切换

- 候选版生成
- 影子观察
- 稳定版切换
- 回退旧版本
- 模型文件损坏时保持旧版本继续服务

### B.4 模式语义

- `shadow` 模式下 `decision_candidate=block` 但 `enforced_action=allow`
- `assist` 模式下仅高置信解析器和正向约束可阻断
- `selective_enforce` 模式下仅批准路由/字段允许弱规则组合进入阻断
