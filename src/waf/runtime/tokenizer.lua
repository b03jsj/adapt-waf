local logger           = require("core.logger")

local ngx_re           = ngx.re
local _gmatch          = ngx_re.gmatch

local _M = {}

local tokenize_pcre = {
    common = {
        -- 注释 / 绕过
        comment_re = [[/\*\*/|--|#]],
        -- 运算 / 结构符号
        op_re      = [[<|>|=|\(|\)|:|/|;|'|"|\[|\]|\{|\}|\.|\+|%|\|\||&&|,]],
        -- 类代码单词（函数名 / 关键字 / 标识符）
        word_re    = [[\b[a-zA-Z_][a-zA-Z0-9_\.]{1,63}\b]],
        -- 纯数字
        number_re  = [[\b\d+\b]],
    }
}

function _M.tokenize(str)
    local tokens = {}
    if not str or str == "" then
        return tokens
    end

    logger.debug('拆解最小化token开始，str: ' , str)

    for m in _gmatch(str, tokenize_pcre.common.comment_re, "jo") do
        logger.debug('拆解最小化token，min token：' , m[0])

        tokens["__comment:" .. m[0]] = true
    end

    for m in _gmatch(str, tokenize_pcre.common.op_re, "jo") do
        logger.debug('拆解最小化token，min token：' , m[0])

        tokens["__op:" .. m[0]] = true
    end

    for m in _gmatch(str, tokenize_pcre.common.number_re, "jo") do
        logger.debug('拆解最小化token，min token：' , m[0])

        tokens["__num:" .. m[0]] = true
    end

    for m in _gmatch(str, tokenize_pcre.common.word_re, "jo") do
        logger.debug('拆解最小化token，min token：' , m[0])

        tokens["__word:" .. m[0]] = true
    end

    return tokens
end

return _M
