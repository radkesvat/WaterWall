#!/usr/bin/env bash

# Covers: runtime exit0 plus every expected packet-report line, and no stdout report leak. Setup:
# private report/core/logs, two default workers and owned runtime PID. Limits: report expectations
# belong to the case; runtime deadline unchanged. CTest: packet-analysis cases via
# add_waterwall_packet_analysis_test.


set -euo pipefail
shopt -s nullglob

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <waterwall-binary> <case-dir> <timeout-seconds>" >&2
  exit 2
fi

binary_path=$(realpath "$1")
case_dir=$(realpath "$2")
timeout_seconds=$3

source "$(dirname "$(realpath "$0")")/case_run_dir.lib.sh"
source "$(dirname "$(realpath "$0")")/support/shell/runner.lib.sh"

trap 'status=$?; remove_case_run_dir "$status"; exit "$status"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
prepare_case_run_dir "$case_dir"
run_dir=$case_run_dir
generated_core_json="$run_dir/core.json"
pid=""

dump_logs() {
  ww_test_dump_logs "$run_dir/stdout.log" "$run_dir"/log/*.log
}

show_stdout_on_success() {
  ww_test_show_stdout_on_success
}

finish_success() {
  if show_stdout_on_success; then
    dump_logs
  fi

  exit 0
}

cleanup() {
  local cleanup_status=$?
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    ww_test_stop_child "$pid" || true
  fi

  remove_case_run_dir "$cleanup_status"
  exit "$cleanup_status"
}

trap cleanup EXIT

# The run directory is a fresh copy, so no stale packet report can satisfy this
# run; drop one only if the case directory itself carries a checked-in leftover.
rm -f "$run_dir/packet-receiver-report.txt"

workers=2
if [[ -f "$run_dir/workers.txt" ]]; then
  workers=$(tr -d '[:space:]' < "$run_dir/workers.txt")
  if [[ ! "$workers" =~ ^[1-9][0-9]*$ ]]; then
    echo "Invalid workers.txt in case directory: expected a positive integer, got '$workers'" >&2
    exit 2
  fi
fi

ww_test_write_core "$generated_core_json" "$workers" client false omit

(
  cd "$run_dir"
  exec "$binary_path" >stdout.log 2>&1
) &
pid=$!

deadline=$((SECONDS + timeout_seconds))

while kill -0 "$pid" 2>/dev/null; do
  if (( SECONDS >= deadline )); then
    echo "Timed out after ${timeout_seconds}s waiting for Waterwall to exit" >&2
    dump_logs
    exit 1
  fi

  sleep 0.2
done

set +e
wait "$pid"
status=$?
set -e
pid=""

if [[ $status -ne 0 ]]; then
  echo "Waterwall exited with non-zero status=$status" >&2
  dump_logs
  exit 1
fi

report_file="$run_dir/packet-receiver-report.txt"
if [[ ! -f "$report_file" ]]; then
  echo "Missing packet receiver report file" >&2
  dump_logs
  exit 1
fi

if [[ ! -f "$run_dir/expected-report.txt" ]]; then
  echo "Missing expected-report.txt in case directory" >&2
  exit 2
fi

while IFS= read -r expected_line || [[ -n "$expected_line" ]]; do
  [[ -n "$expected_line" ]] || continue
  if ! grep -qF "$expected_line" "$report_file"; then
    echo "Report did not contain expected line: $expected_line" >&2
    cat "$report_file" >&2
    exit 1
  fi
done < "$run_dir/expected-report.txt"

if grep -qF "PacketReceiver report" "$run_dir/stdout.log"; then
  echo "PacketReceiver report leaked to stdout" >&2
  cat "$run_dir/stdout.log" >&2
  exit 1
fi

finish_success
