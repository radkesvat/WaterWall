#!/usr/bin/env bash

# Run an integration case that must fail for one specific, observable reason.

set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 <case-runner> <waterwall-binary> <case-dir> <timeout-seconds> <expected-output>" >&2
  exit 2
fi

case_runner=$1
binary_path=$2
case_dir=$3
timeout_seconds=$4
expected_output=$5
captured_output=$(mktemp)

cleanup() {
  rm -f "$captured_output"
}
trap cleanup EXIT

set +e
"$case_runner" "$binary_path" "$case_dir" "$timeout_seconds" >"$captured_output" 2>&1
status=$?
set -e

cat "$captured_output"

if [[ $status -eq 0 ]]; then
  echo "Expected Waterwall case to fail, but it succeeded." >&2
  exit 1
fi

if ! grep -Fq -- "$expected_output" "$captured_output"; then
  echo "Waterwall failed without the expected diagnostic: $expected_output" >&2
  exit 1
fi

exit 0
