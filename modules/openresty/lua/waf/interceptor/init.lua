local access_phase = require("waf.interceptor.phases.access_phase")
local log_phase = require("waf.interceptor.phases.log_phase")

local _M = {}

---初始化 worker 级别状态。
function _M.init_worker()
    access_phase.init_worker()
    log_phase.init_worker()
end

---执行 access 阶段拦截链路。
function _M.run_access()
    access_phase.handle()
end

---执行 log 阶段后处理。
function _M.run_log()
    log_phase.handle()
end

return _M
