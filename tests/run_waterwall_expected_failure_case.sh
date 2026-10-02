#!/usr/bin/env bash

# Covers: exact permitted nonzero status and required diagnostic, rejecting
# signal/reserved/hard-abort/clean/wrong-diagnostic results. Setup: retained capture and explicit
# receipt for the underlying private run; enclosing verdict owns cleanup. CTest: negative
# integration registrations and waterwall.expected_failure_runner.


# Run an integration case that must fail for one specific, observable reason.

set -euo pipefail
source "$(dirname "$(realpath "$0")")/support/shell/runner.lib.sh"

readonly MIN_SIGNAL_EXIT_STATUS=128
readonly FIRST_RESERVED_EXIT_STATUS=125
readonly LAST_RESERVED_EXIT_STATUS=127
readonly HARD_ABORT_MARKER="SignalManager: aborting immediately, registered cleanup is SKIPPED"

if [[ $# -lt 5 || $# -gt 6 ]]; then
  echo "usage: $0 <case-runner> <waterwall-binary> <case-dir> <timeout-seconds> <expected-output> [expected-status]" >&2
  exit 2
fi

case_runner=$1
binary_path=$2
case_dir=$3
timeout_seconds=$4
expected_output=$5
expected_failure_exit_status=${6:-1}

if [[ ! "$expected_failure_exit_status" =~ ^[1-9][0-9]*$ ||
      $expected_failure_exit_status -ge $MIN_SIGNAL_EXIT_STATUS ||
      ($expected_failure_exit_status -ge $FIRST_RESERVED_EXIT_STATUS &&
       $expected_failure_exit_status -le $LAST_RESERVED_EXIT_STATUS) ]]; then
  echo "Expected status must be between 1 and $((MIN_SIGNAL_EXIT_STATUS - 1)), excluding reserved statuses 125-127." >&2
  exit 2
fi

source "$(dirname "$(realpath "$0")")/case_run_dir.lib.sh"
capture_dir=$(mktemp -d "${TMPDIR:-/tmp}/waterwall-expected-XXXXXX")
captured_output="$capture_dir/output.log"
run_root_file="$capture_dir/run-root.txt"
printf "Run artifacts: %s\n" "$capture_dir" >&2

cleanup() {
  local status=$?
  if [[ -s "$run_root_file" ]]; then
    case_run_root=$(<"$run_root_file")
    remove_case_run_dir "$status"
  fi
  ww_test_finish_directory "$capture_dir" "$status"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

set +e
WATERWALL_TEST_RUN_ROOT_FILE="$run_root_file" \
  "$case_runner" "$binary_path" "$case_dir" "$timeout_seconds" >"$captured_output" 2>&1
status=$?
set -e

cat "$captured_output"

if [[ $status -eq 0 ]]; then
  echo "Expected Waterwall case to fail, but it succeeded." >&2
  exit 1
fi

if [[ $status -ge $MIN_SIGNAL_EXIT_STATUS ]]; then
  echo "Waterwall terminated by a signal or exception (status=$status)." >&2
  exit 1
fi

if [[ $status -ge $FIRST_RESERVED_EXIT_STATUS && $status -le $LAST_RESERVED_EXIT_STATUS ]]; then
  echo "Case runner failed with reserved status=$status." >&2
  exit 1
fi

if [[ $status -ne $expected_failure_exit_status ]]; then
  echo "Waterwall case exited with unexpected status=$status; expected $expected_failure_exit_status." >&2
  exit 1
fi

if grep -Fq -- "$HARD_ABORT_MARKER" "$captured_output"; then
  echo "Waterwall used the hard-abort path instead of the expected orderly failure." >&2
  exit 1
fi

if ! grep -Fq -- "$expected_output" "$captured_output"; then
  echo "Waterwall failed without the expected diagnostic: $expected_output" >&2
  exit 1
fi

exit 0
