#!/usr/bin/env bash

# Regression coverage for private-run fixture precedence, probe deadlines and
# cleanup when private-run setup fails.

set -euo pipefail

case "${WATERWALL_RUNNER_EDGE_CHILD:-}" in
  speedtest)
    [[ "$(<server.crt)" == "$EXPECTED_SPEEDTEST_CERT" ]]
    [[ "$(<server.key)" == "$EXPECTED_SPEEDTEST_KEY" ]]
    exit 0
    ;;
  probe)
    trap '' TERM
    exec sleep 30
    ;;
esac

if [[ $# -ne 5 ]]; then
  echo "usage: $0 <case-runner> <speedtest-runner> <probe-runner> <packet-runner> <case-run-dir-helper>" >&2
  exit 2
fi

case_runner=$1
speedtest_runner=$2
probe_runner=$3
packet_runner=$4
case_run_dir_helper=$5
script_path=$(realpath "$0")
test_root=$(mktemp -d "${TMPDIR:-/tmp}/waterwall-runner-edge-test-XXXXXX")

cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT

fixture_tests_dir="$test_root/tests"
case_dir="$fixture_tests_dir/cases/probe_case"
speedtest_dir="$fixture_tests_dir/speedtests/tls_case"
shared_dir="$fixture_tests_dir/speedtests/_shared"
mkdir -p "$case_dir" "$speedtest_dir" "$shared_dir"

printf '%s\n' '# unused by the fake probe process' >"$case_dir/probe.py"
printf '%s\n' 'stale certificate' >"$speedtest_dir/server.crt"
printf '%s\n' 'stale key' >"$speedtest_dir/server.key"
printf '%s\n' 'canonical certificate' >"$shared_dir/server.crt"
printf '%s\n' 'canonical key' >"$shared_dir/server.key"

speedtest_tmp="$test_root/speedtest-tmp"
mkdir -p "$speedtest_tmp"
WATERWALL_TEST_KEEP_RUN_DIR='' \
  WATERWALL_RUNNER_EDGE_CHILD=speedtest \
  EXPECTED_SPEEDTEST_CERT='canonical certificate' \
  EXPECTED_SPEEDTEST_KEY='canonical key' \
  TMPDIR="$speedtest_tmp" \
  bash "$speedtest_runner" "$script_path" "$speedtest_dir" 5

if compgen -G "$speedtest_tmp/waterwall-case-*" >/dev/null; then
  echo "Speedtest runner leaked its private run directory." >&2
  exit 1
fi

probe_tmp="$test_root/probe-tmp"
mkdir -p "$probe_tmp"
set +e
probe_output=$(
  WATERWALL_TEST_KEEP_RUN_DIR='' \
    WATERWALL_RUNNER_EDGE_CHILD=probe \
    TMPDIR="$probe_tmp" \
    bash "$probe_runner" "$script_path" "$case_dir" 1 "$script_path" 2>&1
)
probe_status=$?
set -e

if [[ $probe_status -ne 124 ]]; then
  echo "Probe runner returned $probe_status instead of timeout status 124." >&2
  printf '%s\n' "$probe_output" >&2
  exit 1
fi
if [[ "$probe_output" != *"Timed out after 1s waiting for probe completion."* ]]; then
  echo "Probe runner did not report its requested timeout." >&2
  printf '%s\n' "$probe_output" >&2
  exit 1
fi
if compgen -G "$probe_tmp/waterwall-case-*" >/dev/null; then
  echo "Probe runner leaked its private run directory after timeout." >&2
  exit 1
fi

fake_bin="$test_root/fake-bin"
mkdir -p "$fake_bin"
ln -s "$script_path" "$fake_bin/mkdir"

assert_setup_failure_is_clean() {
  local label=$1
  local tmp_dir=$2
  shift 2

  mkdir -p "$tmp_dir"
  if WATERWALL_TEST_KEEP_RUN_DIR='' TMPDIR="$tmp_dir" PATH="$fake_bin:$PATH" "$@" >/dev/null 2>&1; then
    echo "$label unexpectedly succeeded with a failing mkdir." >&2
    exit 1
  fi

  if compgen -G "$tmp_dir/waterwall-case-*" >/dev/null; then
    echo "$label leaked its private run directory after setup failure." >&2
    exit 1
  fi
}

assert_setup_failure_is_clean \
  "Case runner" "$test_root/case-setup-tmp" \
  bash "$case_runner" "$script_path" "$case_dir" 1
assert_setup_failure_is_clean \
  "Speedtest runner" "$test_root/speedtest-setup-tmp" \
  bash "$speedtest_runner" "$script_path" "$speedtest_dir" 1
assert_setup_failure_is_clean \
  "Probe runner" "$test_root/probe-setup-tmp" \
  bash "$probe_runner" "$script_path" "$case_dir" 1 "$script_path"
assert_setup_failure_is_clean \
  "Packet-analysis runner" "$test_root/packet-setup-tmp" \
  bash "$packet_runner" "$script_path" "$case_dir" 1

# The argument also ensures CTest fails if this helper is moved or omitted.
[[ -f "$case_run_dir_helper" ]]

echo "Test-runner edge-case tests passed."
