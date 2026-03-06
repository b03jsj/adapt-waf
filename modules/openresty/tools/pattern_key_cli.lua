local info = debug.getinfo(1, "S")
local script_path = info and info.source and info.source:sub(2) or arg[0]
local script_dir = script_path:match("(.*/)")
local module_root = script_dir and (script_dir .. "../lua") or "./lua"

package.path = table.concat({
    module_root .. "/?.lua",
    module_root .. "/?/init.lua",
    package.path
}, ";")

-- CLI 只验证 pattern_key 构造，不依赖 ngx 运行时能力。
ngx = ngx or {}

local pattern_key = require("waf.interceptor.core.pattern_key")

local function safe(index)
    return arg[index] or "-"
end

if #arg < 8 then
    io.stderr:write("usage: lua pattern_key_cli.lua <method> <route_key> <content_type> <surface> <field_name> <json_path> <detector> <signature>\n")
    os.exit(1)
end

local output = pattern_key.build({
    method = safe(1),
    route_key = safe(2),
    content_type = safe(3),
    surface = safe(4),
    field_name = safe(5),
    json_path = safe(6),
    detector = safe(7),
    detector_signature = safe(8)
})

io.write(output, "\n")
