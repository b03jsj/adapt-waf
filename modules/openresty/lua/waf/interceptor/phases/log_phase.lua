local json_log = require("waf.interceptor.util.json_log")
local reputation_blacklist = require("waf.interceptor.core.reputation_blacklist")
local config = require("waf.interceptor.core.config")

local _M = {}

local function set_log_target(prefix, loggable, json_line)
    ngx.var[prefix .. "_loggable"] = loggable and "1" or "0"
    ngx.var[prefix .. "_json"] = loggable and json_line or "-"
end

function _M.init_worker()
    -- 预留：后续可在此初始化定时任务。
end

---执行 log 阶段后处理。
---当前请求动作已在 access 阶段确定，不会在此回溯修改。
function _M.handle()
    local runtime = ngx.ctx.waf_runtime
    if not runtime then
        return
    end

    -- 日志阶段更新仅影响后续请求。
    reputation_blacklist.update_from_runtime(runtime)

    local emit_result = json_log.emit(runtime, config.get().logging)
    if not emit_result then
        set_log_target("waf_alert", false, "-")
        set_log_target("waf_sample", false, "-")
        set_log_target("waf_trace", false, "-")
        return
    end

    set_log_target("waf_alert", emit_result.alert_loggable, emit_result.encoded)
    set_log_target("waf_sample", emit_result.sample_loggable, emit_result.encoded)
    set_log_target("waf_trace", emit_result.trace_loggable, emit_result.encoded)
end

return _M
