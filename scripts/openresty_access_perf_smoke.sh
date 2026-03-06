#!/usr/bin/env bash
set -euo pipefail

# 对已启动的 access 链路做轻量顺序时延 smoke。

TARGET_URL="${TARGET_URL:-http://127.0.0.1:8080/}"
REQUESTS="${REQUESTS:-100}"
P95_BUDGET_MS="${P95_BUDGET_MS:-2}"
P99_BUDGET_MS="${P99_BUDGET_MS:-5}"
HARD_LIMIT_MS="${HARD_LIMIT_MS:-10}"

if ! command -v curl >/dev/null 2>&1; then
  echo "missing_command:curl" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "missing_command:python3" >&2
  exit 1
fi

tmp_times="$(mktemp)"
trap 'rm -f "$tmp_times"' EXIT

for ((i = 1; i <= REQUESTS; i++)); do
  curl -o /dev/null -sS -w '%{time_total}\n' "$TARGET_URL" >> "$tmp_times"
done

python3 - <<'PY' "$tmp_times" "$P95_BUDGET_MS" "$P99_BUDGET_MS" "$HARD_LIMIT_MS"
import math
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
p95_budget = float(sys.argv[2])
p99_budget = float(sys.argv[3])
hard_limit = float(sys.argv[4])
values = [float(line.strip()) * 1000.0 for line in path.read_text().splitlines() if line.strip()]
if not values:
    print("no_samples", file=sys.stderr)
    sys.exit(1)

values.sort()

def percentile(sorted_values, q):
    if len(sorted_values) == 1:
        return sorted_values[0]
    pos = (len(sorted_values) - 1) * q
    lower = math.floor(pos)
    upper = math.ceil(pos)
    if lower == upper:
        return sorted_values[lower]
    weight = pos - lower
    return sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight

p50 = percentile(values, 0.50)
p95 = percentile(values, 0.95)
p99 = percentile(values, 0.99)
max_v = max(values)

print(f"latency_ms p50={p50:.3f} p95={p95:.3f} p99={p99:.3f} max={max_v:.3f} samples={len(values)}")

if p95 > p95_budget or p99 > p99_budget or max_v > hard_limit:
    print("perf_smoke_failed", file=sys.stderr)
    sys.exit(1)
PY

echo "openresty_access_perf_smoke_ok"
