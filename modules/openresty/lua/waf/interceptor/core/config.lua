local config_loader = require("waf.common.config_loader")

local _M = {}

local defaults = {
    mode = "shadow",
    logging = {
        trace_enabled = false,
        sample_rate = 0.01
    },
    blacklist = {
        dict_name = "waf_blacklist",
        key_mode = "ip_ua",
        key_delimiter = "|",
        ttl_seconds = 600,
        score_threshold = 3
    },
    limits = {
        hard_timeout_ms = 10
    },
    detector = {
        libinjection_require_module = false,
        libinjection_allow_fallback = true,
        weak_signal_threshold = 2,
        sgd_high_threshold = 0.90,
        model_only_sample_threshold = 0.98
    },
    normalization = {
        active_profile = "norm-v1",
        url_decode_max_passes = 2,
        url_decode_surfaces = {
            query = 2,
            form = 2,
            multipart_filename = 2,
            json = 0,
            text_plain = 0,
            header = 0,
            multipart_text = 0,
            uri = 2
        },
        html_entity_decode_max_passes = 2,
        html_entity_decode_for_xss = true,
        html_entity_decode_for_sqli = false,
        model_feature_max_bytes = 2048
    },
    model = {
        scorer_backend = "lua_ffi",
        allow_model_only_block = false,
        sqli_manifest_path = "/opt/waf/models/sqli/current.manifest.json",
        xss_manifest_path = "/opt/waf/models/xss/current.manifest.json",
        max_hash_dim = 1048576,
        sgd_active_release_states = {
            stable = true
        }
    },
    capture = {
        max_query_fields = 32,
        max_header_fields = 16,
        max_body_fields = 64,
        max_value_bytes = 2048,
        body_parse_max_bytes = 131072,
        body_parse_hard_max_bytes = 1048576,
        allow_temp_file_readback = false,
        allowed_headers = {
            ["x-request-id"] = true,
            ["x-forwarded-for"] = true,
            ["x-real-ip"] = true,
            ["user-agent"] = true,
            ["referer"] = true
        },
        allowed_content_types = {
            ["application/json"] = true,
            ["application/x-www-form-urlencoded"] = true,
            ["text/plain"] = true
        }
    },
    exemptions = {
        dict_name = "waf_control",
        runtime_source = "/opt/waf/policy/exemptions.compiled.json",
        worker_apply_interval_seconds = 1,
        target_key = "exemptions.target_generation",
        target_sha256_key = "exemptions.target_sha256",
        target_size_key = "exemptions.target_size",
        current_key = "exemptions.current_generation",
        status_key = "exemptions.last_publish_status",
        error_key = "exemptions.last_error",
        publish_ts_key = "exemptions.last_publish_ts"
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

    if root then
        local interceptor_cfg = root.interceptor
        if type(interceptor_cfg) == "table" then
            deep_merge(merged, interceptor_cfg)
        else
            -- 兼容直接平铺拦截配置的旧格式。
            deep_merge(merged, root)
        end
    else
        ngx.log(ngx.ERR, "拦截配置加载失败，使用默认配置 path=", config_path, " err=", tostring(err))
    end

    state.config = merged
    state.initialized = true
end

---加载运行时配置（配置来源：conf/waf-config.json）。
function _M.get()
    if not state.initialized then
        init_once()
    end
    return state.config
end

return _M
