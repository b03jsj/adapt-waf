local _M = {}

local _lower  = string.lower

function _M.normalize(str)
    if not str or str == "" then
        return ""
    end

    -- URL decode
    str = ngx.unescape_uri(str)

    -- HTML entity decode（简化版）
    str = str:gsub("&lt;", "<")
             :gsub("&gt;", ">")
             :gsub("&quot;", '"')
             :gsub("&#39;", "'")

    -- 小写
    str = _lower(str)

    return str
end

return _M
