local _M = {}

---执行策略生成的请求动作。
---仅 access 阶段允许调用 ngx.exit。
function _M.apply(decision)
    if not decision then
        return
    end

    if decision.final_action == "block" then
        return ngx.exit(decision.status or ngx.HTTP_FORBIDDEN)
    end
end

return _M
