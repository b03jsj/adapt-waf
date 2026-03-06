local cjson = require("cjson.safe")
local generation_store = require("waf.admin.core.generation_store")
local exemptions = require("waf.interceptor.core.exemptions")
local detector = require("waf.interceptor.core.detector")

local _M = {}

---处理 status 接口，返回当前节点代次与生效状态。
function _M.handle()
    local status = generation_store.status()
    local runtime_exemptions = exemptions.status()
    status.runtime_exemptions = runtime_exemptions
    status.runtime_detector = detector.status()
    status.node_id = ngx.var.hostname or "unknown"
    status.last_apply_ts = runtime_exemptions.last_apply_ts or status.last_publish_ts

    ngx.status = ngx.HTTP_OK
    ngx.say(cjson.encode(status))
end

return _M
