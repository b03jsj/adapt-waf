#!/usr/bin/env bash
set -euo pipefail

# 对已启动的 OpenResty 管理面执行最小 publish/status smoke。

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENRESTY_URL="${OPENRESTY_URL:-http://127.0.0.1:18080}"
OPENRESTY_CONFIG="${OPENRESTY_CONFIG:-$ROOT_DIR/modules/openresty/conf/waf-config.json}"
FIXTURE_FILE="${FIXTURE_FILE:-$ROOT_DIR/modules/shared-spec/fixtures/exemptions.compiled.sample.json}"
GENERATION="${GENERATION:-$(date +%s)}"
OPERATOR="${OPERATOR:-smoke}"
REASON="${REASON:-admin_publish_smoke}"

require_bin() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing_command:$1" >&2
    exit 1
  fi
}

require_bin curl
require_bin python3

tmp_payload="$(mktemp)"
tmp_headers="$(mktemp)"
trap 'rm -f "$tmp_payload" "$tmp_headers"' EXIT

python3 - <<'PY' "$OPENRESTY_CONFIG" "$FIXTURE_FILE" "$GENERATION" "$OPERATOR" "$REASON" "$tmp_payload" "$tmp_headers"
import base64
import hashlib
import json
import pathlib
import secrets
import sys
import time

config_path = pathlib.Path(sys.argv[1])
fixture_path = pathlib.Path(sys.argv[2])
generation = int(sys.argv[3])
operator = sys.argv[4]
reason = sys.argv[5]
payload_path = pathlib.Path(sys.argv[6])
headers_path = pathlib.Path(sys.argv[7])

config = json.loads(config_path.read_text())
fixture = json.loads(fixture_path.read_text())
fixture["generation"] = generation
fixture["publish_id"] = f"pub_smoke_{generation}"
compiled = json.dumps(fixture, separators=(",", ":"), ensure_ascii=False).encode()
compiled_sha256 = hashlib.sha256(compiled).hexdigest()
body = {
    "publish_id": fixture["publish_id"],
    "generation": generation,
    "compiled_sha256": f"sha256:{compiled_sha256}",
    "compiled_size": len(compiled),
    "compiled_content_base64": base64.b64encode(compiled).decode(),
    "operator": operator,
    "reason": reason,
    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
secret = config["admin"]["auth"]["shared_secret"]
timestamp = str(int(time.time()))
nonce = secrets.token_hex(8)
body_sha256 = hashlib.sha256(raw).hexdigest()
signature = hashlib.sha256(f"{timestamp}|{nonce}|{body_sha256}|{secret}".encode()).hexdigest()
payload_path.write_bytes(raw)
headers_path.write_text(
    "\n".join([
        f"X-Waf-Timestamp: {timestamp}",
        f"X-Waf-Nonce: {nonce}",
        f"X-Waf-Signature: {signature}",
    ])
)
PY

echo "[1/3] publish"
curl -sS -X POST "$OPENRESTY_URL/_waf/internal/exemptions/publish" \
  -H "Content-Type: application/json" \
  -H "$(sed -n '1p' "$tmp_headers")" \
  -H "$(sed -n '2p' "$tmp_headers")" \
  -H "$(sed -n '3p' "$tmp_headers")" \
  --data-binary @"$tmp_payload"
echo

echo "[2/3] poll status"
python3 - <<'PY' "$OPENRESTY_URL" "$GENERATION"
import json
import sys
import time
import urllib.request

base = sys.argv[1]
generation = int(sys.argv[2])
deadline = time.time() + 12

while time.time() < deadline:
    with urllib.request.urlopen(base + "/_waf/internal/exemptions/status") as resp:
        data = json.loads(resp.read().decode())
    current_generation = int(data.get("current_generation", 0))
    target_generation = int(data.get("target_generation", 0))
    status = data.get("last_apply_status", "unknown")
    print(f"status current={current_generation} target={target_generation} apply={status}")
    if current_generation >= generation and target_generation >= generation and status == "ok":
        sys.exit(0)
    time.sleep(1)

print("publish_apply_timeout", file=sys.stderr)
sys.exit(1)
PY

echo "[3/3] healthz"
curl -sS "$OPENRESTY_URL/_waf/internal/healthz"
echo
echo "openresty_admin_publish_smoke_ok generation=$GENERATION"
