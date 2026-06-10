#!/usr/bin/env bash

# Low-level Waterwall integration-case runner.
#
# Purpose:
# - run exactly one tests/cases/<name> directory against a chosen Waterwall binary
# - create a temporary core.json so the case only needs to provide config.json
# - fail on crash, early exit, missing success marker, or timeout
# - print logs on failure for easier debugging
#
# Typical usage:
#   tests/run_waterwall_case.sh \
#     build/linux-gcc-x64/Release/Waterwall \
#     tests/cases/disturber_passthrough \
#     60
#
# Notes:
# - most users should prefer running registered cases through ctest
# - ctest uses this script underneath for each registered test case
# - success/fail is decided inside Waterwall by TesterClient/TesterServer
# - this script only watches for the built-in tester success marker so it knows when to stop Waterwall

set -euo pipefail
shopt -s nullglob

readonly TESTER_SUCCESS_REGEX='TesterClient: all [0-9]+ worker lines completed successfully'
readonly DEFAULT_TEST_WORKERS=4
readonly TEST_RAM_PROFILE='client'
readonly SIGTERM_EXIT_STATUS=$((128 + 15))

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <waterwall-binary> <case-dir> <timeout-seconds>" >&2
  exit 2
fi

binary_path=$(realpath "$1")
case_dir=$(realpath "$2")
timeout_seconds=$3

run_dir=$(mktemp -d)
pid=""
success_seen=0

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

show_stdout_on_success() {
  case "${WATERWALL_TEST_SHOW_STDOUT_ON_SUCCESS:-}" in
    1|true|TRUE|True|yes|YES|Yes|on|ON|On)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

finish_success() {
  if show_stdout_on_success && [[ -f "$run_dir/stdout.log" ]]; then
    echo "===== stdout.log ====="
    cat "$run_dir/stdout.log"
  fi

  exit 0
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
  "$binary_path" >"$run_dir/stdout.log" 2>&1
) &
pid=$!

deadline=$((SECONDS + timeout_seconds))

while true; do
  if grep -Eq "$TESTER_SUCCESS_REGEX" "$run_dir"/log/network*.log 2>/dev/null; then
    success_seen=1
    break
  fi

  if ! kill -0 "$pid" 2>/dev/null; then
    set +e
    wait "$pid"
    status=$?
    set -e

    if grep -Eq "$TESTER_SUCCESS_REGEX" "$run_dir"/log/network*.log 2>/dev/null; then
      success_seen=1
    fi

    if [[ $status -eq 0 && $success_seen -eq 1 ]]; then
      finish_success
    fi

    if [[ $success_seen -eq 1 && $status -eq $SIGTERM_EXIT_STATUS ]]; then
      finish_success
    fi

    if [[ $success_seen -eq 1 ]]; then
      echo "Waterwall exited after the success marker with non-zero status=$status." >&2
      dump_logs
      exit 1
    fi

    echo "Waterwall exited before the expected success marker was observed (exit=$status)." >&2
    dump_logs
    exit 1
  fi

  if (( SECONDS >= deadline )); then
    echo "Timed out after ${timeout_seconds}s waiting for tester success marker matching: $TESTER_SUCCESS_REGEX" >&2
    dump_logs
    exit 1
  fi

  sleep 0.2
done

kill -TERM "$pid" 2>/dev/null || true
set +e
wait "$pid"
status=$?
set -e
pid=""

if [[ $status -ne 0 && $status -ne $SIGTERM_EXIT_STATUS ]]; then
  echo "Waterwall exited after the success marker with non-zero status=$status." >&2
  dump_logs
  exit 1
fi

finish_success
