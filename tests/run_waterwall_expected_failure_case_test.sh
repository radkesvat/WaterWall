#!/usr/bin/env bash

# Regression coverage for expected-failure status and diagnostic validation.

set -euo pipefail

case "${1:-}" in
  fake-expected)
    echo "expected diagnostic"
    exit 1
    ;;
  fake-signal)
    echo "expected diagnostic"
    exit 139
    ;;
  fake-timeout)
    echo "expected diagnostic"
    exit 124
    ;;
  fake-clean)
    echo "expected diagnostic"
    exit 0
    ;;
  fake-wrong-diagnostic)
    echo "different diagnostic"
    exit 1
    ;;
esac

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <expected-failure-runner>" >&2
  exit 2
fi

expected_failure_runner=$1

if ! bash "$expected_failure_runner" "$0" fake-expected unused 1 "expected diagnostic" >/dev/null 2>&1; then
  echo "Expected-failure runner rejected the expected status and diagnostic." >&2
  exit 1
fi

if ! bash "$expected_failure_runner" "$0" fake-timeout unused 1 "expected diagnostic" 124 >/dev/null 2>&1; then
  echo "Expected-failure runner rejected an explicitly expected non-signal status." >&2
  exit 1
fi

for rejected_mode in fake-signal fake-timeout fake-clean fake-wrong-diagnostic; do
  if bash "$expected_failure_runner" "$0" "$rejected_mode" unused 1 "expected diagnostic" >/dev/null 2>&1; then
    echo "Expected-failure runner accepted invalid result: $rejected_mode" >&2
    exit 1
  fi
done

echo "Expected-failure runner tests passed."
