local config = require("waf.admin.core.config")

local _M = {}

local function get_dict()
    local dict_name = config.get().generation.dict_name
    return ngx.shared[dict_name]
end

---获取当前生效代次。
function _M.get_current_generation()
    local dict = get_dict()
    if not dict then
        return 0
    end
    return dict:get(config.get().generation.current_key) or 0
end

---获取目标代次。
function _M.get_target_generation()
    local dict = get_dict()
    if not dict then
        return 0
    end
    return dict:get(config.get().generation.target_key) or 0
end

---获取当前与目标中的最大代次。
function _M.get_max_generation()
    local current = _M.get_current_generation()
    local target = _M.get_target_generation()
    if current >= target then
        return current
    end
    return target
end

---推进目标代次与元信息。
function _M.set_target(generation, sha256, size)
    local dict = get_dict()
    if not dict then
        return false, "dict_missing"
    end

    local cfg = config.get().generation
    dict:set(cfg.target_key, generation)
    dict:set(cfg.sha256_key, sha256)
    dict:set(cfg.size_key, size)
    dict:set(cfg.status_key, "ok")
    dict:delete(cfg.error_key)
    if cfg.publish_ts_key then
        dict:set(cfg.publish_ts_key, ngx.now())
    end
    return true, nil
end

---更新当前代次（通常在 worker 生效后调用）。
function _M.set_current(generation)
    local dict = get_dict()
    if not dict then
        return false, "dict_missing"
    end
    dict:set(config.get().generation.current_key, generation)
    return true, nil
end

---写入发布失败状态。
function _M.set_failed(err)
    local dict = get_dict()
    if not dict then
        return
    end
    dict:set(config.get().generation.status_key, "failed")
    dict:set(config.get().generation.error_key, err or "unknown_error")
end

---读取发布状态。
function _M.status()
    local dict = get_dict()
    if not dict then
        return {
            current_generation = 0,
            target_generation = 0,
            last_apply_status = "failed",
            last_error = "dict_missing"
        }
    end

    return {
        current_generation = dict:get(config.get().generation.current_key) or 0,
        target_generation = dict:get(config.get().generation.target_key) or 0,
        last_apply_status = dict:get(config.get().generation.status_key) or "pending",
        last_error = dict:get(config.get().generation.error_key),
        target_sha256 = dict:get(config.get().generation.sha256_key) or "-",
        target_size = dict:get(config.get().generation.size_key) or 0,
        last_publish_ts = dict:get(config.get().generation.publish_ts_key)
    }
end

return _M
