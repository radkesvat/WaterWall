#!/usr/bin/env bash

# Centralized test-lane runner for WaterWall integration tests.
# Supports adaptive parallel jobs for deterministic functional tests
# and serial execution for support, external, speed, and privileged lanes.

set -euo pipefail

usage() {
  cat <<EOF >&2
usage: $0 <lane> [test-dir] [config] [extra ctest args...]

Lanes:
  support      Production policy and harness tests (serial)
  functional   Deterministic functional tests in isolated network namespaces (adaptive parallel jobs)
  external     External network tests on host network (serial)
  speed        Speed tests (serial)
  privileged   Privileged tests requiring root/CAP_NET_ADMIN (serial)
  all          Run support, functional, external, and speed lanes in explicit sequence
  preflight    Verify Linux user and network namespace capabilities for isolation
EOF
  exit 2
}

if [[ $# -lt 1 ]]; then
  usage
fi

lane=$1
shift

test_dir=""
if [[ $# -ge 1 && "$1" != -* ]]; then
  test_dir=$1
  shift
fi

if [[ -z "${test_dir}" ]]; then
  if [[ -f "tests/waterwall_test_network_mode.txt" || -f "waterwall_test_network_mode.txt" || -f "CTestTestfile.cmake" ]]; then
    test_dir="."
  elif [[ -d "build/linux" && (-f "build/linux/tests/waterwall_test_network_mode.txt" || -f "build/linux/waterwall_test_network_mode.txt" || -f "build/linux/CTestTestfile.cmake") ]]; then
    test_dir="build/linux"
  elif [[ -d "build/linux-gcc-x64" && (-f "build/linux-gcc-x64/tests/waterwall_test_network_mode.txt" || -f "build/linux-gcc-x64/waterwall_test_network_mode.txt" || -f "build/linux-gcc-x64/CTestTestfile.cmake") ]]; then
    test_dir="build/linux-gcc-x64"
  else
    test_dir="."
  fi
fi

config="Release"
if [[ $# -ge 1 && "$1" != -* ]]; then
  config=$1
  shift
fi

extra_ctest_args=("$@")

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
wrapper_script="${script_dir}/run_in_network_namespace.sh"

mode_file=""
for candidate in \
  "${test_dir}/tests/waterwall_test_network_mode.txt" \
  "${test_dir}/waterwall_test_network_mode.txt"; do
  if [[ -f "${candidate}" ]]; then
    mode_file="${candidate}"
    break
  fi
done

if [[ -z "$mode_file" ]]; then
  echo "error: network mode file 'waterwall_test_network_mode.txt' not found in '${test_dir}'. Please configure with CMake first." >&2
  exit 1
fi

mode=$(tr -d '[:space:]' < "${mode_file}")
if [[ "$mode" != "isolated" && "$mode" != "host-serial" ]]; then
  echo "error: invalid network mode '${mode}' in '${mode_file}'. Expected 'isolated' or 'host-serial'." >&2
  exit 1
fi

check_netns_capability() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "error: network namespace isolation requires Linux" >&2
    exit 1
  fi

  if ! "${wrapper_script}" bash -c 'ip link show dev lo >/dev/null 2>&1' 2>/dev/null; then
    cat <<'EOF' >&2
error: network namespace capability check failed.
WaterWall integration tests in isolated mode require unprivileged user and
network namespaces (unshare --user --map-root-user --net) with loopback support.

Common causes:
  - Kernel unprivileged user namespaces disabled (sysctl kernel.unprivileged_userns_clone=1)
  - Container runtime / seccomp profile blocking unshare(CLONE_NEWUSER | CLONE_NEWNET)
  - Missing util-linux (unshare) or iproute2 (ip) packages

To run tests serially on the host network without isolation, reconfigure CMake with:
  -DWATERWALL_ENABLE_INTEGRATION_TEST_NETNS=OFF
EOF
    exit 1
  fi
}

if [[ "$lane" == "preflight" ]]; then
  if [[ "$mode" == "host-serial" ]]; then
    echo "Notice: Network namespace isolation is disabled in build tree '${test_dir}' (mode: host-serial). Preflight skipped."
    exit 0
  fi
  check_netns_capability
  echo "Network namespace capability preflight passed."
  exit 0
fi

ensure_lane_preflight() {
  if [[ "${mode}" == "host-serial" ]]; then
    echo "Notice: Network namespace isolation is disabled in build tree '${test_dir}' (mode: host-serial). Running tests sequentially on host network."
    return 0
  fi
  check_netns_capability
}

calculate_jobs() {
  if [[ "${mode}" == "host-serial" ]]; then
    echo 1
    return 0
  fi

  if [[ -n "${WATERWALL_INTEGRATION_TEST_JOBS:-}" ]]; then
    if [[ "$WATERWALL_INTEGRATION_TEST_JOBS" =~ ^[1-9][0-9]*$ ]]; then
      echo "$WATERWALL_INTEGRATION_TEST_JOBS"
      return 0
    else
      echo "error: invalid WATERWALL_INTEGRATION_TEST_JOBS='${WATERWALL_INTEGRATION_TEST_JOBS}': expected a positive integer" >&2
      exit 2
    fi
  fi

  local cpus=1
  if command -v nproc >/dev/null 2>&1; then
    cpus=$(nproc)
  elif command -v getconf >/dev/null 2>&1; then
    cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
  fi

  if [[ ! "$cpus" =~ ^[1-9][0-9]*$ ]]; then
    cpus=1
  fi

  # jobs = min(32, max(4, 4 * available CPUs))
  local calculated=$(( 4 * cpus ))
  if (( calculated < 4 )); then
    calculated=4
  fi
  if (( calculated > 32 )); then
    calculated=32
  fi
  echo "$calculated"
}

run_ctest() {
  local parallel_jobs=$1
  shift
  local ctest_bin="${CTEST_EXECUTABLE:-ctest}"
  local ctest_cmd=("$ctest_bin")
  if [[ ${#extra_ctest_args[@]} -gt 0 ]]; then
    ctest_cmd+=("${extra_ctest_args[@]}")
  fi
  if [[ -n "$test_dir" ]]; then
    ctest_cmd+=("--test-dir" "$test_dir")
  fi
  ctest_cmd+=("-C" "$config" "--output-on-failure" "--parallel" "$parallel_jobs")
  ctest_cmd+=("$@")

  "${ctest_cmd[@]}"
}

case "$lane" in
  support)
    echo "Running production support policy and harness tests (serial)..."
    run_ctest 1 -L 'policy|test-harness' -LE 'integration'
    ;;

  functional)
    ensure_lane_preflight
    cpus=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
    jobs=$(calculate_jobs)
    if [[ "${mode}" == "isolated" ]]; then
      echo "Running deterministic functional integration tests (detected CPUs: ${cpus}, CTest jobs: ${jobs})..."
    fi
    run_ctest "$jobs" -L integration -LE 'privileged|speedtest|external-network'
    ;;

  external)
    echo "Running external network integration tests (serial)..."
    run_ctest 1 -L external-network -LE speedtest
    ;;

  speed)
    ensure_lane_preflight
    echo "Running speed tests (serial)..."
    run_ctest 1 -L speedtest
    ;;

  privileged)
    ensure_lane_preflight
    echo "Running privileged integration tests (serial)..."
    run_ctest 1 -L privileged
    ;;

  all)
    ensure_lane_preflight
    echo "=== Stage 1: Support tests (serial) ==="
    run_ctest 1 -L 'policy|test-harness' -LE 'integration'

    cpus=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
    jobs=$(calculate_jobs)
    echo "=== Stage 2: Deterministic functional integration tests (detected CPUs: ${cpus}, CTest jobs: ${jobs}) ==="
    run_ctest "$jobs" -L integration -LE 'privileged|speedtest|external-network'

    echo "=== Stage 3: External network integration tests (serial) ==="
    run_ctest 1 -L external-network -LE speedtest

    echo "=== Stage 4: Speed tests (serial) ==="
    run_ctest 1 -L speedtest
    ;;

  *)
    echo "Unknown lane: $lane" >&2
    usage
    ;;
esac
