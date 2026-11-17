#!/usr/bin/env bash

# Covers: actual WireGuard cookie-load exchange through a recording relay and the ordinary runtime
# runner. Checks: readiness, generic case verdict and final trace verifier, with original
# force-system-load setting. Setup: owned relay PID and retained trace/runtime roots. CTest:
# WireGuard cookie integration case.


set -euo pipefail

if [[ $# -lt 5 || $# -gt 7 ]]; then
  echo "usage: $0 <generic-runner> <waterwall-binary> <case-dir> <timeout-seconds> <python> [cookie|junk|endpoint] [workers]" >&2
  exit 2
fi

generic_runner=$1
binary_path=$2
case_dir=$3
timeout_seconds=$4
python_executable=$5
relay_options=()
load_environment=(WATERWALL_TEST_FORCE_SYSTEM_LOAD=1)
if [[ "${6:-cookie}" == junk ]]; then
  relay_options=(--junk --server-port 26751 --listen-port 26750)
  load_environment=()
elif [[ "${6:-cookie}" == endpoint ]]; then
  relay_options=(--endpoint-probe)
fi
source "$(dirname "$(realpath "$0")")/case_run_dir.lib.sh"
source "$(dirname "$(realpath "$0")")/support/shell/runner.lib.sh"
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/waterwall-cookie-XXXXXX")
echo "Run artifacts: $test_dir" >&2
run_root_file="$test_dir/run-root.txt"
trace_file="$test_dir/trace.jsonl"
ready_file="$test_dir/ready"
relay_pid=""

if [[ -n "${7:-}" ]]; then
  cp -a "$case_dir" "$test_dir/case"
  case_dir="$test_dir/case"
  printf '%s\n' "$7" > "$case_dir/workers.txt"
fi

cleanup() {
  local cleanup_status=$?
  if [[ -n "$relay_pid" ]] && kill -0 "$relay_pid" 2>/dev/null; then
    ww_test_stop_child "$relay_pid" || true
  fi
  if [[ -s "$run_root_file" ]]; then
    case_run_root=$(<"$run_root_file")
    remove_case_run_dir "$cleanup_status"
  fi
  ww_test_finish_directory "$test_dir" "$cleanup_status"
  exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$python_executable" "$(dirname "$generic_runner")/wireguard_cookie_relay.py" \
  --trace-file "$trace_file" \
  --ready-file "$ready_file" "${relay_options[@]}" &
relay_pid=$!

for _ in {1..100}; do
  if [[ -e "$ready_file" ]]; then
    break
  fi
  if ! kill -0 "$relay_pid" 2>/dev/null; then
    wait "$relay_pid"
    exit 1
  fi
  sleep 0.05
done

if [[ ! -e "$ready_file" ]]; then
  echo "WireGuard cookie relay did not become ready" >&2
  exit 1
fi

env "${load_environment[@]}" WATERWALL_TEST_RUN_ROOT_FILE="$run_root_file" \
  "$generic_runner" "$binary_path" "$case_dir" "$timeout_seconds"

kill -TERM "$relay_pid"
wait "$relay_pid"
relay_pid=""

"$python_executable" "$(dirname "$generic_runner")/wireguard_cookie_relay.py" \
  --verify \
  --trace-file "$trace_file" "${relay_options[@]}"
