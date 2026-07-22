#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 <generic-runner> <waterwall-binary> <case-dir> <timeout-seconds> <python>" >&2
  exit 2
fi

generic_runner=$1
binary_path=$2
case_dir=$3
timeout_seconds=$4
python_executable=$5
test_dir=$(mktemp -d)
trace_file="$test_dir/trace.jsonl"
ready_file="$test_dir/ready"
relay_pid=""

cleanup() {
  if [[ -n "$relay_pid" ]] && kill -0 "$relay_pid" 2>/dev/null; then
    kill -TERM "$relay_pid" 2>/dev/null || true
    wait "$relay_pid" 2>/dev/null || true
  fi
  rm -rf "$test_dir"
}
trap cleanup EXIT

"$python_executable" "$(dirname "$generic_runner")/wireguard_cookie_relay.py" \
  --trace-file "$trace_file" \
  --ready-file "$ready_file" &
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

WATERWALL_TEST_FORCE_SYSTEM_LOAD=1 \
  "$generic_runner" "$binary_path" "$case_dir" "$timeout_seconds"

kill -TERM "$relay_pid"
wait "$relay_pid"
relay_pid=""

"$python_executable" "$(dirname "$generic_runner")/wireguard_cookie_relay.py" \
  --verify \
  --trace-file "$trace_file"
