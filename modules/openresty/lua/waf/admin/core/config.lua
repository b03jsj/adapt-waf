local config_loader = require("waf.common.config_loader")

local _M = {}

local defaults = {
    snapshot = {
        runtime_file = "/opt/waf/policy/exemptions.compiled.json",
        tmp_suffix = ".tmp"
    },
    generation = {
        dict_name = "waf_control",
        current_key = "exemptions.current_generation",
        target_key = "exemptions.target_generation",
        sha256_key = "exemptions.target_sha256",
        size_key = "exemptions.target_size",
        publish_ts_key = "exemptions.last_publish_ts",
        status_key = "exemptions.last_publish_status",
        error_key = "exemptions.last_error"
    },
    auth = {
        require_mtls = false,
        require_signature = true,
        shared_secret = "change_me"
    }
}

local state = {
    initialized = false,
    config = nil
}

local function deep_copy(source)
    if type(source) ~= "table" then
        return source
    end

    local target = {}
    for key, value in pairs(source) do
        target[key] = deep_copy(value)
    end
    return target
end

local function deep_merge(target, override)
    if type(target) ~= "table" or type(override) ~= "table" then
        return target
    end

    for key, value in pairs(override) do
        if type(value) == "table" and type(target[key]) == "table" then
            deep_merge(target[key], value)
        else
            target[key] = value
        end
    end
    return target
end

local function init_once()
    local merged = deep_copy(defaults)
    local config_path = config_loader.default_config_path()
    local root, err = config_loader.load(config_path)
    if root and type(root.admin) == "table" then
        deep_merge(merged, root.admin)
    elseif not root then
        ngx.log(ngx.ERR, "管理配置加载失败，使用默认配置 path=", config_path, " err=", tostring(err))
    end
    state.config = merged
    state.initialized = true
end

---返回管理端配置（配置来源：conf/waf-config.json）。
function _M.get()
    if not state.initialized then
        init_once()
    end
    return state.config
end

return _M
