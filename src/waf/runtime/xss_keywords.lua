local _M = {}

_M.js_funcs = {
    alert      = true,
    confirm    = true,
    prompt     = true,
    eval       = true,
    settimeout = true,
    setinterval= true,
    ["function"]   = true
}

_M.dom_objs = {
    document = true,
    window   = true,
    location = true,
    cookie   = true,
    top      = true,
    parent   = true,
    self     = true
}

_M.html_tags = {
    script = true,
    img    = true,
    svg    = true,
    iframe = true,
    object = true,
    embed  = true
}

_M.events = {
    onerror     = true,
    onload      = true,
    onclick     = true,
    onmouseover = true,
    onfocus     = true,
    onmouseenter= true,
    onmouseleave= true,
    onsubmit    = true
}

_M.protocols = {
    javascript = true,
    data       = true
}

function _M.is_strong(token)
    token = token:lower()

    return _M.js_funcs[token]
    or _M.dom_objs[token]
    or _M.html_tags[token]
    or _M.events[token]
    or _M.protocols[token]
end

return _M
