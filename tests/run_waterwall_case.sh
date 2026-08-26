#!/usr/bin/env bash

# Low-level Waterwall integration-case runner.
#
# Purpose:
# - run exactly one tests/cases/<name> directory against a chosen Waterwall binary
# - copy the case into a private run directory so generated files stay out of the
#   source tree and concurrent tests cannot clobber each other
# - create a generated core.json so the case only needs to provide config.json
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
readonly DEFAULT_SUCCESS_EXIT_GRACE_SECONDS=0.5
readonly SUCCESS_EXIT_GRACE_POLL_SECONDS=0.05
readonly SIGTERM_EXIT_STATUS=$((128 + 15))
readonly TEST_TIMEOUT_EXIT_STATUS=124
readonly TEST_RUNNER_FAILURE_EXIT_STATUS=125

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <waterwall-binary> <case-dir> <timeout-seconds>" >&2
  exit 2
fi

binary_path=$(realpath "$1")
case_dir=$(realpath "$2")
timeout_seconds=$3

source "$(dirname "$(realpath "$0")")/case_run_dir.lib.sh"

trap remove_case_run_dir EXIT
prepare_case_run_dir "$case_dir"
run_dir=$case_run_dir
generated_core_json="$run_dir/core.json"
success_exit_grace_seconds=${WATERWALL_TEST_SUCCESS_EXIT_GRACE_SECONDS:-$DEFAULT_SUCCESS_EXIT_GRACE_SECONDS}
pid=""
success_seen=0

calculate_success_exit_grace_checks() {
  local seconds=$1

  awk -v seconds="$seconds" -v interval="$SUCCESS_EXIT_GRACE_POLL_SECONDS" '
    BEGIN {
      if (seconds !~ /^[0-9]+([.][0-9]+)?$/) {
        exit 1
      }

      printf "%d\n", int((seconds / interval) + 0.999999)
    }
  '
}

if ! success_exit_grace_checks=$(calculate_success_exit_grace_checks "$success_exit_grace_seconds"); then
  echo "Invalid WATERWALL_TEST_SUCCESS_EXIT_GRACE_SECONDS: expected a non-negative number, got '$success_exit_grace_seconds'" >&2
  exit 2
fi

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
  if show_stdout_on_success; then
    dump_logs
  fi

  exit 0
}

finish_after_success_exit_status() {
  local status=$1

  if [[ $status -eq 0 || $status -eq $SIGTERM_EXIT_STATUS ]]; then
    finish_success
  fi

  echo "Waterwall exited after the success marker with non-zero status=$status." >&2
  dump_logs
  exit "$status"
}

wait_for_success_graceful_exit() {
  local i
  local status

  for ((i = 0; i < success_exit_grace_checks; i++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      set +e
      wait "$pid"
      status=$?
      set -e
      pid=""
      finish_after_success_exit_status "$status"
    fi

    sleep "$SUCCESS_EXIT_GRACE_POLL_SECONDS"
  done
}

cleanup() {
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi

  # The run directory is a private copy, so files Waterwall mutates in place
  # (users.json and its backup) die with it and never touch the case directory.
  remove_case_run_dir
}

trap cleanup EXIT

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

while true; do
  if grep -Eq "$TESTER_SUCCESS_REGEX" "$run_dir"/log/network*.log /dev/null 2>/dev/null; then
    success_seen=1
    break
  fi

  if ! kill -0 "$pid" 2>/dev/null; then
    set +e
    wait "$pid"
    status=$?
    set -e

    if grep -Eq "$TESTER_SUCCESS_REGEX" "$run_dir"/log/network*.log /dev/null 2>/dev/null; then
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
      exit "$status"
    fi

    echo "Waterwall exited before the expected success marker was observed (exit=$status)." >&2
    dump_logs
    if [[ $status -eq 0 ]]; then
      # Distinguish a clean but semantically incomplete run from Waterwall's
      # own failure status so expected-failure tests cannot accept it.
      exit "$TEST_RUNNER_FAILURE_EXIT_STATUS"
    fi
    exit "$status"
  fi

  if (( SECONDS >= deadline )); then
    echo "Timed out after ${timeout_seconds}s waiting for tester success marker matching: $TESTER_SUCCESS_REGEX" >&2
    dump_logs
    exit "$TEST_TIMEOUT_EXIT_STATUS"
  fi

  sleep 0.2
done

wait_for_success_graceful_exit

kill -TERM "$pid" 2>/dev/null || true
set +e
wait "$pid"
status=$?
set -e
pid=""

finish_after_success_exit_status "$status"
