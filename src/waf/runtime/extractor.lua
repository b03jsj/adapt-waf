local tokenizer  = require("waf.runtime.tokenizer")
local normalizer = require("waf.runtime.normalizer")

local _M = {}

local inspect_headers = {
    "cookie",
}

local function extract_param(map, name, value)
    if not value or value == "" then
        return
    end

    value = normalizer.normalize(value)
    local tokens = tokenizer.tokenize(value)
    if not next(tokens) then
        return
    end

    map[name] = tokens
end

function _M.extract(api_ctx)
    local params_tokens = {}

    -- query 参数
    for k, v in pairs(api_ctx.req.uri_args or {}) do
        extract_param(params_tokens, k, v)
    end

    -- header（可选）
    for _, k in ipairs(inspect_headers) do
        local v = api_ctx.req.headers[k]

        extract_param(params_tokens, "header:" .. k, v)
    end

    api_ctx.params_tokens = params_tokens

    return params_tokens
end

return _M
