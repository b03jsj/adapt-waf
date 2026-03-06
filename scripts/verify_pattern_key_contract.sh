#!/usr/bin/env bash
set -euo pipefail

# 对照 OpenResty Lua 与 Java 的 pattern_key_v1 实现，确保公共契约一致。

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE_FILE="$ROOT_DIR/modules/shared-spec/fixtures/pattern-key-v1-cases.tsv"
JAVA_SRC_DIR="$ROOT_DIR/modules/java-control-plane/src/main/java"
JAVA_BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$JAVA_BUILD_DIR"' EXIT

if command -v lua >/dev/null 2>&1; then
  LUA_BIN="lua"
elif command -v luajit >/dev/null 2>&1; then
  LUA_BIN="luajit"
else
  echo "missing_command:lua_or_luajit" >&2
  exit 1
fi

if ! command -v javac >/dev/null 2>&1; then
  echo "missing_command:javac" >&2
  exit 1
fi

javac -encoding UTF-8 -d "$JAVA_BUILD_DIR" \
  "$JAVA_SRC_DIR/com/adaptwaf/controlplane/service/PatternKeyService.java" \
  "$JAVA_SRC_DIR/com/adaptwaf/controlplane/tools/PatternKeyCli.java"

line_no=0
while IFS=$'\t' read -r method route_key content_type surface field_name json_path detector signature expected; do
  line_no=$((line_no + 1))
  [[ -z "$method" ]] && continue
  [[ "$method" =~ ^# ]] && continue

  java_out="$(java -cp "$JAVA_BUILD_DIR" com.adaptwaf.controlplane.tools.PatternKeyCli \
    "$method" "$route_key" "$content_type" "$surface" "$field_name" "$json_path" "$detector" "$signature")"
  lua_out="$("$LUA_BIN" "$ROOT_DIR/modules/openresty/tools/pattern_key_cli.lua" \
    "$method" "$route_key" "$content_type" "$surface" "$field_name" "$json_path" "$detector" "$signature")"

  if [[ "$java_out" != "$expected" ]]; then
    echo "java_pattern_key_mismatch line=$line_no expected=$expected actual=$java_out" >&2
    exit 1
  fi
  if [[ "$lua_out" != "$expected" ]]; then
    echo "lua_pattern_key_mismatch line=$line_no expected=$expected actual=$lua_out" >&2
    exit 1
  fi
  if [[ "$java_out" != "$lua_out" ]]; then
    echo "cross_runtime_pattern_key_mismatch line=$line_no java=$java_out lua=$lua_out" >&2
    exit 1
  fi
  echo "pattern_key_ok line=$line_no"
done < "$FIXTURE_FILE"

echo "verify_pattern_key_contract_ok"
