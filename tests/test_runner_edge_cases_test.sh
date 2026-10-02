#!/usr/bin/env bash

# Covers: credential precedence, fake TERM-ignoring probe deadlines, success/failure/skip
# retention and expected-failure cleanup. Setup: private synthetic cases and subprocesses; no
# shipped runtime fixture. CTest: waterwall.test_runner_edge_cases.


# Regression coverage for private-run fixture precedence, probe deadlines and
# artifact retention, enclosing expected-failure verdicts and setup failures.

set -euo pipefail
source "$(dirname "$(realpath "$0")")/support/shell/runner.lib.sh"

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
  expected)
    echo "expected diagnostic"
    exit 1
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
echo "Run artifacts: $test_root" >&2


cleanup() {
  local status=$?
  ww_test_finish_directory "$test_root" "$status"
  exit "$status"
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
if ! compgen -G "$probe_tmp/waterwall-case-*" >/dev/null; then
  echo "Probe runner removed its private run directory after timeout." >&2
  exit 1
fi

fake_bin="$test_root/fake-bin"
mkdir -p "$fake_bin"
ln -s "$script_path" "$fake_bin/mkdir"

assert_setup_failure_is_retained() {
  local label=$1
  local tmp_dir=$2
  shift 2

  mkdir -p "$tmp_dir"
  if WATERWALL_TEST_KEEP_RUN_DIR='' TMPDIR="$tmp_dir" PATH="$fake_bin:$PATH" "$@" >/dev/null 2>&1; then
    echo "$label unexpectedly succeeded with a failing mkdir." >&2
    exit 1
  fi

  if ! compgen -G "$tmp_dir/waterwall-case-*" >/dev/null; then
    echo "$label removed its private run directory after setup failure." >&2
    exit 1
  fi
}

assert_setup_failure_is_retained \
  "Case runner" "$test_root/case-setup-tmp" \
  bash "$case_runner" "$script_path" "$case_dir" 1
assert_setup_failure_is_retained \
  "Speedtest runner" "$test_root/speedtest-setup-tmp" \
  bash "$speedtest_runner" "$script_path" "$speedtest_dir" 1
assert_setup_failure_is_retained \
  "Probe runner" "$test_root/probe-setup-tmp" \
  bash "$probe_runner" "$script_path" "$case_dir" 1 "$script_path"
assert_setup_failure_is_retained \
  "Packet-analysis runner" "$test_root/packet-setup-tmp" \
  bash "$packet_runner" "$script_path" "$case_dir" 1

# The argument also ensures CTest fails if this helper is moved or omitted.
[[ -f "$case_run_dir_helper" ]]

for verdict in 0 7 77; do
  for keep in '' 1; do
    retention_tmp="$test_root/retention-$verdict-${keep:-default}"
    mkdir -p "$retention_tmp"
    set +e
    TMPDIR="$retention_tmp" WATERWALL_TEST_KEEP_RUN_DIR="$keep" \
      bash -c 'set -euo pipefail; source "$1";
        trap '\''status=$?; remove_case_run_dir "$status"; exit "$status"'\'' EXIT;
        prepare_case_run_dir "$2"; printf artifact >"$case_run_dir/result"; exit "$3"' \
        unused "$case_run_dir_helper" "$case_dir" "$verdict" >/dev/null 2>&1
    status=$?
    set -e
    [[ $status -eq $verdict ]]
    if [[ $verdict -ne 0 || "$keep" == 1 ]]; then
      compgen -G "$retention_tmp/waterwall-case-*" >/dev/null
    elif compgen -G "$retention_tmp/waterwall-case-*" >/dev/null; then
      echo "Successful shell run retained artifacts without an override." >&2
      exit 1
    fi
  done
done

# The wrapper owns cleanup until its status/diagnostic checks accept the failure.
expected_runner="$(dirname "$case_runner")/run_waterwall_expected_failure_case.sh"
for diagnostic in 'expected diagnostic' 'wrong diagnostic'; do
  expected_tmp="$test_root/expected-${diagnostic// /-}"
  mkdir -p "$expected_tmp"
  set +e
  WATERWALL_RUNNER_EDGE_CHILD=expected WATERWALL_TEST_KEEP_RUN_DIR='' TMPDIR="$expected_tmp" \
    bash "$expected_runner" "$case_runner" "$script_path" "$case_dir" 5 "$diagnostic" >/dev/null 2>&1
  status=$?
  set -e
  if [[ "$diagnostic" == 'expected diagnostic' ]]; then
    [[ $status -eq 0 ]]
    if compgen -G "$expected_tmp/waterwall-case-*" >/dev/null; then
      echo "Accepted expected failure retained artifacts as a failed run." >&2
      exit 1
    fi
  else
    [[ $status -ne 0 ]]
    compgen -G "$expected_tmp/waterwall-case-*" >/dev/null
  fi
done

echo "Test-runner edge-case tests passed."
