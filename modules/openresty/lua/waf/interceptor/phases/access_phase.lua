local request_context = require("waf.interceptor.core.request_context")
local reputation_blacklist = require("waf.interceptor.core.reputation_blacklist")
local detector = require("waf.interceptor.core.detector")
local exemptions = require("waf.interceptor.core.exemptions")
local budget = require("waf.interceptor.core.budget")
local policy = require("waf.interceptor.core.policy")
local pattern_key = require("waf.interceptor.core.pattern_key")
local config = require("waf.interceptor.core.config")
local decision_executor = require("waf.interceptor.core.decision_executor")

local _M = {}

local function pick(preferred, fallback)
    if preferred and preferred ~= "" and preferred ~= "-" then
        return preferred
    end
    return fallback
end

local function build_timeout_runtime(ctx, budget_state, stage)
    local exceeded, elapsed_ms = budget.exceeded(budget_state, stage)
    if not exceeded then
        return nil
    end

    local timeout_decision = policy.decide_timeout(stage, elapsed_ms, budget_state.timeout_ms)
    return {
        context = ctx,
        decision = timeout_decision,
        signals = {
            detector = "none",
            detector_signature = "-",
            parser_hit = false
        }
    }
end

function _M.init_worker()
    reputation_blacklist.init()
    exemptions.init_worker()
    detector.init_worker()
end

---执行 access 阶段请求拦截流程。
---该函数内所有操作必须是非阻塞且低时延的。
function _M.handle()
    local budget_state = budget.start(config.get().limits.hard_timeout_ms)
    local ctx = request_context.build()

    local runtime = build_timeout_runtime(ctx, budget_state, "normalization")
    if runtime then
        ngx.ctx.waf_runtime = runtime
        decision_executor.apply(runtime.decision)
        return
    end

    local blacklist_hit, blacklist_meta = reputation_blacklist.hit(ctx)
    if blacklist_hit then
        local decision = policy.decide_blacklist_hit(ctx, blacklist_meta)
        ngx.ctx.waf_runtime = {
            context = ctx,
            decision = decision,
            signals = {
                reputation_blacklist_hit = true
            }
        }
        decision_executor.apply(decision)
        return
    end

    runtime = build_timeout_runtime(ctx, budget_state, "blacklist")
    if runtime then
        ngx.ctx.waf_runtime = runtime
        decision_executor.apply(runtime.decision)
        return
    end

    local signals = detector.inspect(ctx)
    ctx.detector = signals.detector
    ctx.detector_signature = signals.detector_signature
    ctx.surface = pick(signals.matched_surface, ctx.surface)
    ctx.field_name = pick(signals.matched_field_name, ctx.field_name)
    ctx.json_path = pick(signals.matched_json_path, ctx.json_path)
    ctx.matched_value = signals.matched_value or ""
    ctx.pattern_key = pattern_key.build(ctx)
    ctx.pattern_key_hash = pattern_key.sha256(ctx.pattern_key)

    runtime = build_timeout_runtime(ctx, budget_state, "detector")
    if runtime then
        ngx.ctx.waf_runtime = runtime
        decision_executor.apply(runtime.decision)
        return
    end

    local exemption_match = exemptions.match(ctx, signals)
    signals.exemption_applied = exemption_match.applied
    signals.exemption_id = exemption_match.exemption_id
    signals.exemption_match_scope = exemption_match.match_scope
    signals.exemption_match_key = exemption_match.match_key
    signals.pattern_state = exemption_match.pattern_state
    signals.exemptions_generation = exemption_match.generation

    runtime = build_timeout_runtime(ctx, budget_state, "exemption_match")
    if runtime then
        ngx.ctx.waf_runtime = runtime
        decision_executor.apply(runtime.decision)
        return
    end

    local decision = policy.decide(ctx, signals, exemption_match)
    local exceeded, elapsed_ms = budget.exceeded(budget_state, "policy")
    if exceeded then
        decision = policy.decide_timeout("policy", elapsed_ms, budget_state.timeout_ms)
    else
        decision.elapsed_ms = elapsed_ms
        decision.hard_timeout_ms = budget_state.timeout_ms
        decision.timeout_stage = ""
    end

    ngx.ctx.waf_runtime = {
        context = ctx,
        decision = decision,
        signals = signals
    }

    decision_executor.apply(decision)
end

return _M
