local _M = {}

---启动请求级检测预算。
---@param timeout_ms number
---@return table
function _M.start(timeout_ms)
    return {
        started_at = ngx.now(),
        timeout_ms = timeout_ms or 10
    }
end

---计算当前预算已消耗时间（毫秒）。
---@param budget table
---@return number
function _M.elapsed_ms(budget)
    return (ngx.now() - budget.started_at) * 1000
end

---检查预算是否超时。
---@param budget table
---@param stage string
---@return boolean, number, string
function _M.exceeded(budget, stage)
    local elapsed = _M.elapsed_ms(budget)
    if elapsed > budget.timeout_ms then
        return true, elapsed, stage
    end
    return false, elapsed, stage
end

return _M
