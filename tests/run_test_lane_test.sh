#!/usr/bin/env bash

# Regression harness test for tests/run_test_lane.sh

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
runner_source="${1:-${script_dir}/run_test_lane.sh}"

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [runner-script]" >&2
  exit 2
fi

if [[ ! -x "${runner_source}" ]]; then
  echo "error: runner script '${runner_source}' not found or not executable" >&2
  exit 2
fi

tmp_dir=$(mktemp -d "/tmp/waterwall_lane_test_XXXXXX")
trap 'rm -rf "${tmp_dir}"' EXIT

# Run an exact copy beside a fake namespace wrapper so this harness also works
# in a build explicitly configured for host-serial fallback because unshare is
# unavailable. The real wrapper has its own focused harness.
runner_script="${tmp_dir}/run_test_lane.sh"
cp -- "${runner_source}" "${runner_script}"
chmod +x "${runner_script}"

fake_wrapper="${tmp_dir}/run_in_network_namespace.sh"
cat <<'EOF' > "${fake_wrapper}"
#!/usr/bin/env bash
exit 0
EOF
chmod +x "${fake_wrapper}"

mock_ctest="${tmp_dir}/mock_ctest.sh"
cat <<'EOF' > "${mock_ctest}"
#!/usr/bin/env bash
echo "MOCK_CTEST_CALL: $@" >> "${MOCK_LOG}"
exit 0
EOF
chmod +x "${mock_ctest}"

export CTEST_EXECUTABLE="${mock_ctest}"
export MOCK_LOG="${tmp_dir}/mock_ctest.log"

# Test 1: Missing mode file fails before running ctest
test_dir_missing="${tmp_dir}/missing_mode_dir"
mkdir -p "${test_dir_missing}"
if "${runner_script}" functional "${test_dir_missing}" >"${tmp_dir}/out1.log" 2>"${tmp_dir}/err1.log"; then
  echo "FAIL: expected missing mode file to fail" >&2
  exit 1
fi
grep -q "network mode file 'waterwall_test_network_mode.txt' not found" "${tmp_dir}/err1.log"

if "${runner_script}" preflight "${test_dir_missing}" >"${tmp_dir}/out1b.log" 2>"${tmp_dir}/err1b.log"; then
  echo "FAIL: expected preflight with a missing mode file to fail" >&2
  exit 1
fi
grep -q "network mode file 'waterwall_test_network_mode.txt' not found" "${tmp_dir}/err1b.log"

# Test 2: Invalid mode token fails
test_dir_invalid="${tmp_dir}/invalid_mode_dir"
mkdir -p "${test_dir_invalid}"
echo "invalid-mode-token" > "${test_dir_invalid}/waterwall_test_network_mode.txt"
if "${runner_script}" functional "${test_dir_invalid}" >"${tmp_dir}/out2.log" 2>"${tmp_dir}/err2.log"; then
  echo "FAIL: expected invalid mode token to fail" >&2
  exit 1
fi
grep -q "invalid network mode 'invalid-mode-token'" "${tmp_dir}/err2.log"

if "${runner_script}" preflight "${test_dir_invalid}" >"${tmp_dir}/out2b.log" 2>"${tmp_dir}/err2b.log"; then
  echo "FAIL: expected preflight with an invalid mode token to fail" >&2
  exit 1
fi
grep -q "invalid network mode 'invalid-mode-token'" "${tmp_dir}/err2b.log"

# Test 3: host-serial mode forces 1 job even with jobs override, skips preflight
test_dir_host="${tmp_dir}/host_serial_dir"
mkdir -p "${test_dir_host}"
echo "host-serial" > "${test_dir_host}/waterwall_test_network_mode.txt"

# 3a. preflight in host-serial skips
out_preflight=$("${runner_script}" preflight "${test_dir_host}")
echo "${out_preflight}" | grep -q "Preflight skipped"

# 3b. functional in host-serial runs with --parallel 1
: > "${MOCK_LOG}"
"${runner_script}" functional "${test_dir_host}" >/dev/null
grep -q -- "--parallel 1" "${MOCK_LOG}"

# 3c. functional in host-serial with WATERWALL_INTEGRATION_TEST_JOBS=16 still forces --parallel 1
: > "${MOCK_LOG}"
WATERWALL_INTEGRATION_TEST_JOBS=16 "${runner_script}" functional "${test_dir_host}" >/dev/null
grep -q -- "--parallel 1" "${MOCK_LOG}"

# 3d. Extra CTest arguments cannot override host-serial scheduling or test tree.
: > "${MOCK_LOG}"
"${runner_script}" functional "${test_dir_host}" Release --parallel 16 --test-dir /tmp/not-the-configured-tree >/dev/null
last_parallel=$(awk '{ for (i = 1; i < NF; i++) if ($i == "--parallel") value = $(i + 1) } END { print value }' "${MOCK_LOG}")
last_test_dir=$(awk '{ for (i = 1; i < NF; i++) if ($i == "--test-dir") value = $(i + 1) } END { print value }' "${MOCK_LOG}")
if [[ "${last_parallel}" != "1" || "${last_test_dir}" != "${test_dir_host}" ]]; then
  echo "FAIL: extra CTest arguments overrode authoritative host-serial settings" >&2
  exit 1
fi

# Test 4: isolated mode uses adaptive/overridden jobs
test_dir_isolated="${tmp_dir}/isolated_dir"
mkdir -p "${test_dir_isolated}"
echo "isolated" > "${test_dir_isolated}/waterwall_test_network_mode.txt"

: > "${MOCK_LOG}"
WATERWALL_INTEGRATION_TEST_JOBS=8 "${runner_script}" functional "${test_dir_isolated}" >/dev/null
grep -q -- "--parallel 8" "${MOCK_LOG}"

# Test 5: Lane label expressions are correctly passed
# 5a. support lane
: > "${MOCK_LOG}"
"${runner_script}" support "${test_dir_isolated}" >/dev/null
grep -q -- "-L policy|test-harness -LE integration" "${MOCK_LOG}"

# 5b. functional lane
: > "${MOCK_LOG}"
"${runner_script}" functional "${test_dir_isolated}" >/dev/null
grep -q -- "-L integration -LE privileged|speedtest|external-network" "${MOCK_LOG}"

# 5c. external lane
: > "${MOCK_LOG}"
"${runner_script}" external "${test_dir_isolated}" >/dev/null
grep -q -- "-L external-network -LE speedtest" "${MOCK_LOG}"

# 5d. speed lane
: > "${MOCK_LOG}"
"${runner_script}" speed "${test_dir_isolated}" >/dev/null
grep -q -- "-L speedtest" "${MOCK_LOG}"

# 5e. privileged lane
: > "${MOCK_LOG}"
"${runner_script}" privileged "${test_dir_isolated}" >/dev/null
grep -q -- "-L privileged" "${MOCK_LOG}"

# Test 6: all runs the four ordinary non-privileged stages exactly once.
: > "${MOCK_LOG}"
"${runner_script}" all "${test_dir_host}" >/dev/null
if [[ $(wc -l < "${MOCK_LOG}") -ne 4 ]]; then
  echo "FAIL: all lane did not invoke exactly four CTest stages" >&2
  exit 1
fi
grep -q -- "-L policy|test-harness -LE integration" "${MOCK_LOG}"
grep -q -- "-L integration -LE privileged|speedtest|external-network" "${MOCK_LOG}"
grep -q -- "-L external-network -LE speedtest" "${MOCK_LOG}"
grep -q -- "-L speedtest" "${MOCK_LOG}"

# Test 7: do not advertise the non-privileged all lane as a full suite.
if "${runner_script}" full "${test_dir_host}" >"${tmp_dir}/out7.log" 2>"${tmp_dir}/err7.log"; then
  echo "FAIL: deprecated full lane alias unexpectedly succeeded" >&2
  exit 1
fi
grep -q "Unknown lane: full" "${tmp_dir}/err7.log"

echo "run_test_lane tests passed."
