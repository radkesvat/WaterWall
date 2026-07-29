#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob

readonly DEFAULT_TEST_WORKERS=1
readonly TEST_RAM_PROFILE='client'
readonly SIGTERM_EXIT_STATUS=$((128 + 15))
readonly TEST_TIMEOUT_EXIT_STATUS=124
readonly CHILD_TERMINATION_GRACE_CHECKS=10
readonly CHILD_TERMINATION_GRACE_POLL_SECONDS=0.05

if [[ $# -lt 4 ]]; then
  echo "usage: $0 <waterwall-binary> <case-dir> <timeout-seconds> <python3>" >&2
  exit 2
fi

binary_path=$(realpath "$1")
case_dir=$(realpath "$2")
timeout_seconds=$3
python_path=$4

source "$(dirname "$(realpath "$0")")/case_run_dir.lib.sh"

trap remove_case_run_dir EXIT
prepare_case_run_dir "$case_dir"
run_dir=$case_run_dir
generated_core_json="$run_dir/core.json"
pid=""
probe_pid=""

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

terminate_child() {
  local child_pid=$1
  local i

  if kill -0 "$child_pid" 2>/dev/null; then
    kill -TERM "$child_pid" 2>/dev/null || true
    for ((i = 0; i < CHILD_TERMINATION_GRACE_CHECKS; i++)); do
      if ! kill -0 "$child_pid" 2>/dev/null; then
        break
      fi
      sleep "$CHILD_TERMINATION_GRACE_POLL_SECONDS"
    done
    if kill -0 "$child_pid" 2>/dev/null; then
      kill -KILL "$child_pid" 2>/dev/null || true
    fi
  fi

  wait "$child_pid" 2>/dev/null || true
}

cleanup() {
  if [[ -n "$probe_pid" ]]; then
    terminate_child "$probe_pid"
    probe_pid=""
  fi

  if [[ -n "$pid" ]]; then
    terminate_child "$pid"
    pid=""
  fi

  # Generated core.json, logs and fixtures live in the private run directory,
  # so removing it is the whole cleanup.
  remove_case_run_dir
}

trap cleanup EXIT

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

cat >"$generated_core_json" <<EOF
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
    "mtu": 1500,
    "try-enabling-bbr": false
  }
}
EOF

(
  cd "$run_dir"
  exec "$binary_path" >stdout.log 2>&1
) &
pid=$!

deadline=$((SECONDS + timeout_seconds))

(
  cd "$run_dir"
  exec "$python_path" "$run_dir/probe.py"
) &
probe_pid=$!

while kill -0 "$probe_pid" 2>/dev/null; do
  if ! kill -0 "$pid" 2>/dev/null; then
    set +e
    wait "$pid"
    status=$?
    set -e
    pid=""

    echo "Waterwall exited before probe completion (exit=$status)." >&2
    dump_logs
    exit 1
  fi

  if ((SECONDS >= deadline)); then
    echo "Timed out after ${timeout_seconds}s waiting for probe completion." >&2
    dump_logs
    exit "$TEST_TIMEOUT_EXIT_STATUS"
  fi

  sleep 0.2
done

set +e
wait "$probe_pid"
probe_status=$?
set -e
probe_pid=""

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
