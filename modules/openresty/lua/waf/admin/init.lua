local publish_handler = require("waf.admin.handlers.publish")
local status_handler = require("waf.admin.handlers.status")
local rollback_handler = require("waf.admin.handlers.rollback")

local _M = {}

---根据请求路径分发管理接口处理器。
function _M.dispatch()
    local uri = ngx.var.uri or ""
    local method = ngx.req.get_method()

    if uri == "/_waf/internal/exemptions/publish" and method == "POST" then
        return publish_handler.handle()
    end

    if uri == "/_waf/internal/exemptions/status" and method == "GET" then
        return status_handler.handle()
    end

    if uri == "/_waf/internal/exemptions/rollback" and method == "POST" then
        return rollback_handler.handle()
    end

    ngx.status = ngx.HTTP_NOT_FOUND
    ngx.say('{"error":"not_found"}')
end

return _M
