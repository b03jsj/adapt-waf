-- 处理和ctx相关
local tablepool       = require("resty.tablepool")
local ngx_re          = require("ngx.re")

local _ngx            = ngx

local _M = {}


local function get_remote_ip(api_ctx)
    local real_ip = api_ctx.req.headers["x-forwarded-for"]

    if real_ip and '' ~= real_ip then
        real_ip = ngx_re.split(real_ip, ",", "jo")[1]
    end

    if not real_ip or '' == real_ip then
        real_ip = api_ctx.req.headers["X-Real-IP"]
    end

    if not real_ip or '' == real_ip then
        real_ip = _ngx.var.remote_addr
    end

    return real_ip
end

function _M.init()
    local _ngx_ctx = _ngx.ctx

    _ngx_ctx.api_ctx          = tablepool.fetch("api_ctx", 0, 64)
    _ngx_ctx.api_ctx.req      = tablepool.fetch("req", 0, 64)

    local api_ctx             = _ngx_ctx.api_ctx

    api_ctx.req.headers       = _ngx.req.get_headers() or {}
    api_ctx.req.uri_args      = _ngx.req.get_uri_args()
    api_ctx.req.client_ip     = get_remote_ip(api_ctx)

    return api_ctx
end

function _M.log(api_ctx)
    tablepool.release("req", api_ctx.req)
    tablepool.release("api_ctx", api_ctx)
end


return _M
