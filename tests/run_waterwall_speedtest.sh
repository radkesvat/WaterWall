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

run_dir=$speedtest_dir
generated_core_json="$run_dir/core.json"
core_created=0
generated_shared_paths=()
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

  if [[ $core_created -eq 1 ]]; then
    rm -f "$generated_core_json"
  fi

  if [[ ${#generated_shared_paths[@]} -gt 0 ]]; then
    rm -rf -- "${generated_shared_paths[@]}"
  fi
}

trap cleanup EXIT

if [[ -e "$generated_core_json" ]]; then
  echo "Refusing to overwrite existing generated core.json in speedtest directory: $generated_core_json" >&2
  exit 2
fi

# Keep generated logs in the speedtest directory, but start each run clean.
rm -rf "$run_dir/stdout.log" "$run_dir/log"

copy_generated_shared_path() {
  local source_path=$1
  local dest_path=$2

  if [[ -e "$dest_path" ]]; then
    if [[ -f "$source_path" && -f "$dest_path" ]] && cmp -s "$source_path" "$dest_path"; then
      return 0
    fi

    echo "Refusing to overwrite existing speedtest fixture: $dest_path" >&2
    exit 2
  fi

  cp -R "$source_path" "$dest_path"
  generated_shared_paths+=("$dest_path")
}

shared_dir="$speedtest_dir/../_shared"
if [[ -d "$shared_dir" ]]; then
  for shared_path in "$shared_dir"/*; do
    [[ -e "$shared_path" ]] || continue
    copy_generated_shared_path "$shared_path" "$run_dir/$(basename "$shared_path")"
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

core_created=1
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
