#!/usr/bin/env bash

# Low-level Waterwall speed-test runner.
#
# Unlike run_waterwall_case.sh, this runner does not wait for TesterClient's
# success marker. SpeedTestClient terminates Waterwall itself; exit status 0 is
# considered success.

set -euo pipefail
shopt -s nullglob

readonly DEFAULT_TEST_WORKERS=4
readonly TEST_RAM_PROFILE='client'

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <waterwall-binary> <speedtest-dir> <timeout-seconds>" >&2
  exit 2
fi

binary_path=$(realpath "$1")
speedtest_dir=$(realpath "$2")
timeout_seconds=$3

source "$(dirname "$(realpath "$0")")/case_run_dir.lib.sh"

trap remove_case_run_dir EXIT
prepare_case_run_dir "$speedtest_dir"
run_dir=$case_run_dir
generated_core_json="$run_dir/core.json"
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

cleanup() {
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi

  # Generated core.json, logs and _shared fixtures all live in the private run
  # directory, so removing it is the whole cleanup.
  remove_case_run_dir
}

trap cleanup EXIT

# Stage the shared fixtures into the private run directory. Certificates beside
# a speedtest are ignored generated artifacts from older in-place runs, so the
# canonical shared certificate and key always replace them. Other fixture names
# may still be overridden by the speedtest.
shared_dir="$speedtest_dir/../_shared"
if [[ -d "$shared_dir" ]]; then
  for shared_path in "$shared_dir"/*; do
    [[ -e "$shared_path" ]] || continue
    shared_name=$(basename "$shared_path")
    run_shared_path="$run_dir/$shared_name"
    if [[ "$shared_name" == "server.crt" || "$shared_name" == "server.key" ]]; then
      rm -f -- "$run_shared_path"
    fi
    if [[ ! -e "$run_shared_path" ]]; then
      cp -R "$shared_path" "$run_shared_path"
    fi
  done
fi

test_workers=$DEFAULT_TEST_WORKERS
if [[ -f "$run_dir/workers.txt" ]]; then
  test_workers=$(tr -d '[:space:]' < "$run_dir/workers.txt")
  if [[ ! "$test_workers" =~ ^[1-9][0-9]*$ ]]; then
    echo "Invalid workers.txt in speedtest directory: expected a positive integer, got '$test_workers'" >&2
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
  "$binary_path" >stdout.log 2>&1
) &
pid=$!

deadline=$((SECONDS + timeout_seconds))

while true; do
  if ! kill -0 "$pid" 2>/dev/null; then
    set +e
    wait "$pid"
    status=$?
    set -e
    pid=""

    if [[ $status -eq 0 ]]; then
      finish_success
    fi

    echo "Waterwall speedtest exited with non-zero status=$status." >&2
    dump_logs
    exit 1
  fi

  if (( SECONDS >= deadline )); then
    echo "Timed out after ${timeout_seconds}s waiting for Waterwall speedtest to exit." >&2
    dump_logs
    exit 1
  fi

  sleep 0.2
done
