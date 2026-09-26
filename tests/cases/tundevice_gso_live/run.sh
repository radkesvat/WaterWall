#!/usr/bin/env bash

# Two WaterWall runs share one private network namespace. The first relies on
# TunDevice's default GSO setting; the second explicitly disables it. Logs are
# inspected after each shutdown, when the reader prints its aggregate count.
set -euo pipefail

readonly SKIP_STATUS=77
readonly TUN_NAME=wwgsolive0
readonly DESTINATION_IP=10.253.82.2
readonly MARK=99
readonly ROUTE_TABLE=100
readonly VETH_OUT=wwgsoout0

if (( $# != 3 )); then
  echo "usage: run.sh <waterwall-binary> <case-dir> <python3>" >&2
  exit 2
fi

binary_path=$(realpath "$1")
case_dir=$(realpath "$2")
python_path=$3
tests_dir=$(dirname "$(dirname "$case_dir")")
source "$tests_dir/case_run_dir.lib.sh"

if [[ "$(uname -s)" != Linux || $(id -u) != 0 || ! -c /dev/net/tun ]]; then
  echo "TUN GSO live test requires Linux, root/CAP_NET_ADMIN and /dev/net/tun"
  exit "$SKIP_STATUS"
fi

if ! command -v ip >/dev/null 2>&1 || ! command -v nsenter >/dev/null 2>&1; then
  echo "TUN GSO live test requires iproute2 and nsenter"
  exit "$SKIP_STATUS"
fi

pid=""
cleanup() {
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    sleep 0.1
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  ip rule delete fwmark "$MARK" lookup "$ROUTE_TABLE" priority 100 >/dev/null 2>&1 || true
  ip route flush table "$ROUTE_TABLE" >/dev/null 2>&1 || true
  ip link delete "$VETH_OUT" >/dev/null 2>&1 || true
  ip link delete "$TUN_NAME" >/dev/null 2>&1 || true
  ip link delete wwgsoinj0 >/dev/null 2>&1 || true
  remove_case_run_dir
}
trap cleanup EXIT

prepare_case_run_dir "$case_dir"
run_dir=$case_run_dir

gso_workers=${WATERWALL_GSO_WORKERS-1}
if [[ ! $gso_workers =~ ^[1-9][0-9]{0,2}$ ]] || (( gso_workers > 255 )); then
  echo "WATERWALL_GSO_WORKERS must be an integer from 1 to 255" >&2
  exit 2
fi

ip link delete "$TUN_NAME" >/dev/null 2>&1 || true
ip rule add fwmark "$MARK" lookup "$ROUTE_TABLE" priority 100

cat >"$run_dir/core.json" <<EOF
{
  "log": {
    "path": "log/",
    "internal": { "loglevel": "DEBUG", "file": "internal.log", "console": true },
    "core":     { "loglevel": "DEBUG", "file": "core.log",     "console": true },
    "network":  { "loglevel": "DEBUG", "file": "network.log",  "console": true },
    "dns":      { "loglevel": "DEBUG", "file": "dns.log",      "console": true }
  },
  "configs": ["config.json"],
  "misc": {
    "workers": $gso_workers,
    "splice": false,
    "ram-profile": "client",
    "mtu": 1500,
    "try-enabling-bbr": false
  }
}
EOF

mode_order=${WATERWALL_GSO_MODE_ORDER:-default,off}
if [[ "$mode_order" != default,off && "$mode_order" != off,default ]]; then
  echo "WATERWALL_GSO_MODE_ORDER must be default,off or off,default" >&2
  exit 2
fi

run_mode() {
  local mode=$1
  local log_path="$run_dir/stdout-$mode.log"
  local probe_path="$run_dir/result-$mode.json"
  local status

  "$python_path" - "$run_dir/config.json" "$mode" <<'PY'
import json
import sys

path, mode = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    config = json.load(stream)
settings = config["nodes"][0]["settings"]
if mode == "off":
    settings["gso"] = False
else:
    settings.pop("gso", None)
with open(path, "w", encoding="utf-8") as stream:
    json.dump(config, stream)
PY

  rm -rf "$run_dir/log"
  (
    cd "$run_dir"
    exec "$binary_path" >"$log_path" 2>&1
  ) &
  pid=$!

  if ! "$python_path" "$run_dir/probe.py" "$mode" "$probe_path"; then
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      pid=""
    fi
    cat "$log_path" >&2
    return 1
  fi

  if ! kill -0 "$pid" 2>/dev/null; then
    cat "$log_path" >&2
    echo "WaterWall exited before $mode probe completed" >&2
    return 1
  fi

  kill -TERM "$pid"
  set +e
  wait "$pid"
  status=$?
  set -e
  pid=""
  if (( status != 0 && status != 143 )); then
    cat "$log_path" >&2
    echo "WaterWall $mode run exited with status $status" >&2
    return 1
  fi

  "$python_path" - "$log_path" "$probe_path" "$mode" <<'PY'
import json
import re
import sys

log_path, probe_path, mode = sys.argv[1:]
log = open(log_path, encoding="utf-8", errors="replace").read()
result = json.load(open(probe_path, encoding="utf-8"))
if mode == "default":
    assert "configured framing: TCPv4 GSO (GSO requested: yes)" in log, "default GSO was not enabled"
    verified_limit = "kernel GSO max segments set to 2048" in log
    warned_limit = "could not set/verify kernel GSO max segments 2048" in log
    assert verified_limit != warned_limit, "kernel GSO limit result was not logged exactly once"
    if verified_limit:
        assert result["interface_gso_max_segs"] == 2048, "interface readback disagrees with successful setup"
    result["gso_limit_result"] = "verified" if verified_limit else "warning"
    summary = re.search(r"GSO reader summary: ordinary=(\d+) aggregates=(\d+) generated=(\d+)", log)
    assert summary, "GSO reader summary missing"
    ordinary, aggregates, generated = map(int, summary.groups())
    assert aggregates > 0 and generated > 2048, (ordinary, aggregates, generated)
    assert "malformed=0 unsupported=0 oversized=0" in log, "valid test packets were rejected"
    result.update({"ordinary_records": ordinary, "gso_aggregates": aggregates, "generated_segments": generated})
else:
    assert "configured framing: raw IP (GSO requested: no)" in log, "explicitly disabled mode was not used"
    assert "GSO reader summary" not in log, "raw-IP mode used the GSO reader"
print(json.dumps(result, sort_keys=True), flush=True)
PY

  ip link delete "$TUN_NAME" >/dev/null 2>&1 || true
}

IFS=, read -r first_mode second_mode <<<"$mode_order"
run_mode "$first_mode"
run_mode "$second_mode"

"$python_path" - "$run_dir/result-default.json" "$run_dir/result-off.json" <<'PY'
import json
import sys

default_path, off_path = sys.argv[1:]
with open(default_path, encoding="utf-8") as stream:
    default = json.load(stream)["kernel_comparison"]
with open(off_path, encoding="utf-8") as stream:
    off = json.load(stream)["kernel_comparison"]
assert default["segments"] == off["segments"] == 3, "comparison fixture did not produce three segments"
assert default["sha256"] == off["sha256"], "converter and kernel produced different wire packets"
print(f"kernel-comparison: 3 identical packets, sha256={default['sha256']}", flush=True)
PY
