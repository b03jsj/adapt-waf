# Shared Spec

该模块是跨子系统契约的唯一规范源。

- `openapi/waf-management-api.yaml`：OpenResty 管理接口定义（publish/status/rollback）
- `openapi/review-control-plane-api.yaml`：Java 审核控制面接口定义（审核、发布、回退、状态）
- `schemas/`：日志与接口 JSON Schema
- `pattern-key/`：`pattern_key_v1` 构造规范

当前已锁定语义：

- OpenResty 管理接口默认鉴权为“请求签名 + 防重放”，`mTLS` 为可选增强
- OpenResty `rollback` 接口默认返回 `501`，历史快照回退由 Java 控制面执行“旧内容新代次 publish”
- `policy_decision_basis` 等枚举必须与运行时代码保持一致

实现模块不得各自定义冲突版本。
