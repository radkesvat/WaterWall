#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob

readonly DEFAULT_TEST_WORKERS=1
readonly TEST_RAM_PROFILE='client'
readonly SIGTERM_EXIT_STATUS=$((128 + 15))

if [[ $# -lt 4 ]]; then
  echo "usage: $0 <waterwall-binary> <case-dir> <timeout-seconds> <python3>" >&2
  exit 2
fi

binary_path=$(realpath "$1")
case_dir=$(realpath "$2")
timeout_seconds=$3
python_path=$4

run_dir=$(mktemp -d)
pid=""

dump_logs() {
  local path
  local paths=(
    "$run_dir/stdout.log"
    "$run_dir"/log/internal*.log
    "$run_dir"/log/core*.log
    "$run_dir"/log/network*.log
    "$run_dir"/log/dns*.log
  )

  for path in "${paths[@]}"; do
    if [[ -f "$path" ]]; then
      echo "===== $(basename "$path") =====" >&2
      cat "$path" >&2
    fi
  done
}

cleanup() {
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi

  rm -rf "$run_dir"
}

trap cleanup EXIT

cp -R "$case_dir"/. "$run_dir"/

if [[ ! -f "$run_dir/server.crt" && -f "$case_dir/../tls_roundtrip/server.crt" ]]; then
  cp "$case_dir/../tls_roundtrip/server.crt" "$run_dir/server.crt"
fi
if [[ ! -f "$run_dir/server.key" && -f "$case_dir/../tls_roundtrip/server.key" ]]; then
  cp "$case_dir/../tls_roundtrip/server.key" "$run_dir/server.key"
fi

test_workers=$DEFAULT_TEST_WORKERS
if [[ -f "$run_dir/workers.txt" ]]; then
  test_workers=$(tr -d '[:space:]' < "$run_dir/workers.txt")
  if [[ ! "$test_workers" =~ ^[1-9][0-9]*$ ]]; then
    echo "Invalid workers.txt in case directory: expected a positive integer, got '$test_workers'" >&2
    exit 2
  fi
fi

cat >"$run_dir/core.json" <<EOF
{
  "log": {
    "path": "log/",
    "internal": { "loglevel": "DEBUG", "file": "internal.log", "console": true },
    "core":     { "loglevel": "DEBUG", "file": "core.log",     "console": true },
    "network":  { "loglevel": "DEBUG", "file": "network.log",  "console": true },
    "dns":      { "loglevel": "DEBUG", "file": "dns.log",      "console": true }
  },
  "configs": [
    "config.json"
  ],
  "misc": {
    "workers": $test_workers,
    "ram-profile": "$TEST_RAM_PROFILE",
    "mtu": 1500
  }
}
EOF

(
  cd "$run_dir"
  exec "$binary_path" >stdout.log 2>&1
) &
pid=$!

set +e
(
  cd "$run_dir"
  "$python_path" "$run_dir/probe.py"
)
probe_status=$?
set -e

if [[ $probe_status -ne 0 ]]; then
  echo "Probe script failed with status=$probe_status" >&2
  dump_logs
  exit "$probe_status"
fi

if ! kill -0 "$pid" 2>/dev/null; then
  set +e
  wait "$pid"
  status=$?
  set -e
  echo "Waterwall exited before probe cleanup (exit=$status)." >&2
  dump_logs
  exit 1
fi

kill -TERM "$pid" 2>/dev/null || true
set +e
wait "$pid"
status=$?
set -e
pid=""

if [[ $status -ne 0 && $status -ne $SIGTERM_EXIT_STATUS ]]; then
  echo "Waterwall exited after probe success with non-zero status=$status." >&2
  dump_logs
  exit 1
fi
