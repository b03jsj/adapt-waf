local cjson = require("cjson.safe")
local auth = require("waf.admin.core.auth")

local _M = {}

---处理 rollback 接口。
---说明：当前节点不直接执行回退，Java 控制面应走“旧快照新代次 publish”流程。
function _M.handle()
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    local body = cjson.decode(raw or "{}") or {}

    local ok, auth_err = auth.authorize(raw or "")
    if not ok then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.say(cjson.encode({ error = auth_err }))
        return
    end

    local generation = body.generation or 0
    local rollback_from_generation = body.rollback_from_generation or 0

    ngx.status = ngx.HTTP_NOT_IMPLEMENTED
    ngx.say(cjson.encode({
        accepted = false,
        generation = generation,
        rollback_from_generation = rollback_from_generation,
        error = "not_implemented_use_publish_republish"
    }))
end

return _M
