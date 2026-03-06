#!/usr/bin/env bash
set -euo pipefail

# 执行不会依赖数据库/服务启动的静态契约校验。

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require_bin() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing_command:$1" >&2
    exit 1
  fi
}

require_bin python3
require_bin rg
require_bin luac

echo "[1/4] 校验 JSON 配置与 schema 语法"
python3 - <<'PY' "$ROOT_DIR"
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
files = [
    root / "modules/openresty/conf/waf-config.json",
    root / "modules/java-control-plane/conf/control-plane-config.json",
    root / "modules/shared-spec/schemas/exemptions-publish-request.schema.json",
    root / "modules/shared-spec/schemas/waf-alert-log.schema.json",
    root / "modules/shared-spec/fixtures/exemptions.compiled.sample.json",
]
for path in files:
    with path.open("rb") as fh:
        json.load(fh)
    print(f"json_ok {path.relative_to(root)}")
PY

if command -v ruby >/dev/null 2>&1; then
  echo "[1b/4] 校验 OpenAPI YAML 语法"
  ruby -e '
    require "yaml"
    ARGV.each do |file|
      YAML.load_file(file)
      puts "yaml_ok #{file}"
    end
  ' \
    "$ROOT_DIR/modules/shared-spec/openapi/waf-management-api.yaml" \
    "$ROOT_DIR/modules/shared-spec/openapi/review-control-plane-api.yaml"
else
  echo "[1b/4] skip_yaml_parse ruby_not_found"
fi

echo "[2/4] 校验 OpenResty Lua 语法"
while IFS= read -r -d '' file; do
  luac -p "$file"
  echo "lua_ok ${file#$ROOT_DIR/}"
done < <(find "$ROOT_DIR/modules/openresty/lua" "$ROOT_DIR/modules/openresty/tools" -type f -name '*.lua' -print0)

echo "[3/4] 检查主文档与 shared-spec 是否残留旧语义"
forbidden_patterns=(
  'parser_hit_assist\b'
  'parser_hit_auto_suggested'
  'waf-exempt compile'
  'init_by_lua\*'
  '必须启用 mTLS 与签名'
  'mTLS_required: true'
)

for pattern in "${forbidden_patterns[@]}"; do
  if rg -n "$pattern" \
    "$ROOT_DIR/docs/openresty-waf-overview.md" \
    "$ROOT_DIR/docs/openresty-waf-implementation.md" \
    "$ROOT_DIR/modules/shared-spec" >/dev/null 2>&1; then
    echo "stale_contract_detected:$pattern" >&2
    exit 1
  fi
done

echo "[4/4] 检查规范源文件存在"
required_files=(
  "$ROOT_DIR/docs/openresty-waf-validation.md"
  "$ROOT_DIR/modules/shared-spec/openapi/waf-management-api.yaml"
  "$ROOT_DIR/modules/shared-spec/openapi/review-control-plane-api.yaml"
  "$ROOT_DIR/modules/shared-spec/pattern-key/pattern_key_v1.md"
)

for file in "${required_files[@]}"; do
  [[ -f "$file" ]] || { echo "missing_required_file:${file#$ROOT_DIR/}" >&2; exit 1; }
  echo "exists ${file#$ROOT_DIR/}"
done

echo "verify_static_contracts_ok"
