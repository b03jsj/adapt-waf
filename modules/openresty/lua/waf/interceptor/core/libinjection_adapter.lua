local config = require("waf.interceptor.core.config")

local _M = {}

local state = {
    loaded = false,
    driver = nil,
    load_error = nil,
    require_module = false,
    allow_fallback = true
}

local function fallback_sqli(value)
    local lowered = string.lower(value or "")
    if lowered:find("' or ", 1, true) or lowered:find("union select", 1, true) then
        return true, "fallback_sqli"
    end
    return false, "-"
end

local function fallback_xss(value)
    local lowered = string.lower(value or "")
    if lowered:find("<script", 1, true) or lowered:find("javascript:", 1, true) then
        return true, "fallback_xss"
    end
    return false, "-"
end

local function try_load()
    if state.loaded then
        return
    end
    state.loaded = true

    local ok, mod = pcall(require, "resty.libinjection")
    if not ok then
        state.load_error = tostring(mod)
        return
    end
    state.driver = mod
end

---初始化 libinjection 适配器。
function _M.init()
    local detector_cfg = config.get().detector
    state.require_module = detector_cfg.libinjection_require_module == true
    state.allow_fallback = detector_cfg.libinjection_allow_fallback ~= false
    try_load()
end

---判断 libinjection 是否可用。
---@return boolean
function _M.available()
    return state.driver ~= nil
end

---执行 SQLi 检测。
---@param value string
---@return boolean, string, string
function _M.sqli(value)
    try_load()
    if state.driver and state.driver.sqli then
        local ok, hit, fingerprint = pcall(state.driver.sqli, value or "")
        if ok and hit then
            return true, tostring(fingerprint or "-"), "libinjection"
        end
        return false, "-", "libinjection"
    end

    if state.allow_fallback then
        local hit, signature = fallback_sqli(value)
        return hit, signature, "fallback"
    end

    return false, "-", "unavailable"
end

---执行 XSS 检测。
---@param value string
---@return boolean, string, string
function _M.xss(value)
    try_load()
    if state.driver and state.driver.xss then
        local ok, hit, fingerprint = pcall(state.driver.xss, value or "")
        if ok and hit then
            return true, tostring(fingerprint or "-"), "libinjection"
        end
        return false, "-", "libinjection"
    end

    if state.allow_fallback then
        local hit, signature = fallback_xss(value)
        return hit, signature, "fallback"
    end

    return false, "-", "unavailable"
end

---返回适配器状态。
---@return table
function _M.status()
    return {
        loaded = state.driver ~= nil,
        load_error = state.load_error,
        require_module = state.require_module,
        allow_fallback = state.allow_fallback
    }
end

---返回“要求强依赖但未加载”状态。
---@return boolean
function _M.hard_unavailable()
    return state.require_module and (state.driver == nil)
end

return _M
