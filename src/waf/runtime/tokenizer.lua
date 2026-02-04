local logger           = require("core.logger")

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


local function add(tokens, t)
    if t and #t > 0 then
        logger.debug('拆解最小化token开始，min token：' , t)

        tokens[t:lower()] = true
    end
end

local function is_pure_digit(t)
    local len = #t
    if len == 0 then return false end
    for i = 1, len do
        local c = t:byte(i)
        if c < 48 or c > 57 then
            return false
        end
    end
    return true
end

function _M.tokenize(str)
    local tokens = {}
    if not str or str == "" then
        return tokens
    end

    logger.debug('拆解最小化token开始，str: ' , str)

    for m in ngx.re.gmatch(str, tokenize_pcre.common.comment_re, "jo") do
        add(tokens, "__comment:" .. m[0])
    end

    for m in ngx.re.gmatch(str, tokenize_pcre.common.op_re, "jo") do
        add(tokens, "__op:" .. m[0])
    end

    for m in ngx.re.gmatch(str, tokenize_pcre.common.number_re, "jo") do
        add(tokens, "__num:" .. m[0])
    end

    for m in ngx.re.gmatch(str, tokenize_pcre.common.word_re, "jo") do
        add(tokens, "__word:" .. m[0])
    end

    return tokens
end

return _M
