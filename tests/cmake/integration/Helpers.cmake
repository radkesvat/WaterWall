# Explicit namespace, prerequisite, marker and benchmark registration contracts.
function(add_waterwall_test_labels test_name)
  set_property(TEST ${test_name} APPEND PROPERTY LABELS ${ARGN})
endfunction()
function(add_waterwall_case_resource_lock test_name case_name)
  set_property(
    TEST ${test_name}
    APPEND PROPERTY RESOURCE_LOCK "waterwall_case_${case_name}"
  )
endfunction()
function(add_waterwall_isolated_test test_name)
  if(WATERWALL_ENABLE_INTEGRATION_TEST_NETNS)
    add_test(
      NAME ${test_name}
      COMMAND
        "${BASH_EXECUTABLE}"
        "${WATERWALL_TEST_SOURCE_ROOT}/run_in_network_namespace.sh"
        ${ARGN}
    )
    add_waterwall_test_labels(${test_name} "network-isolated")
  else()
    add_test(
      NAME ${test_name}
      COMMAND ${ARGN}
    )
    add_waterwall_test_labels(${test_name} "host-network")
  endif()
endfunction()
function(add_waterwall_integration_test_with_timeout test_name case_name timeout_seconds)
  set(case_dir "${WATERWALL_TEST_SOURCE_ROOT}/cases/${case_name}")

  add_waterwall_isolated_test(
    ${test_name}
    "${BASH_EXECUTABLE}"
    "${WATERWALL_TEST_SOURCE_ROOT}/run_waterwall_case.sh"
    "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
    "${case_dir}"
    "${timeout_seconds}"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 120
  )
  add_waterwall_test_labels(${test_name} "integration" "tunnels")
  add_waterwall_case_resource_lock(${test_name} ${case_name})
endfunction()
function(add_waterwall_integration_test test_name case_name)
  add_waterwall_integration_test_with_timeout(${test_name} ${case_name} 30)
endfunction()
function(add_waterwall_external_integration_test_with_timeout test_name case_name timeout_seconds)
  set(case_dir "${WATERWALL_TEST_SOURCE_ROOT}/cases/${case_name}")

  add_test(
    NAME ${test_name}
    COMMAND
      "${BASH_EXECUTABLE}"
      "${WATERWALL_TEST_SOURCE_ROOT}/run_waterwall_case.sh"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
      "${case_dir}"
      "${timeout_seconds}"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 120
      RUN_SERIAL TRUE
  )
  add_waterwall_test_labels(${test_name} "integration" "tunnels" "external-network" "host-network")
  add_waterwall_case_resource_lock(${test_name} ${case_name})
endfunction()
function(add_waterwall_external_integration_test test_name case_name)
  add_waterwall_external_integration_test_with_timeout(${test_name} ${case_name} 30)
endfunction()
function(add_waterwall_wireguard_cookie_test test_name case_name)
  set(case_dir "${WATERWALL_TEST_SOURCE_ROOT}/cases/${case_name}")

  add_waterwall_isolated_test(
    ${test_name}
    "${BASH_EXECUTABLE}"
    "${WATERWALL_TEST_SOURCE_ROOT}/run_wireguard_cookie_case.sh"
    "${WATERWALL_TEST_SOURCE_ROOT}/run_waterwall_case.sh"
    "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
    "${case_dir}"
    "30"
    "${PYTHON3_EXECUTABLE}"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 120
      RESOURCE_LOCK waterwall_wireguard_cookie_ports
  )
  add_waterwall_test_labels(${test_name} "integration" "tunnels" "wireguard" "cookies" "overload")
  add_waterwall_case_resource_lock(${test_name} ${case_name})
endfunction()
function(add_waterwall_skipped_integration_test test_name skip_message)
  add_test(
    NAME ${test_name}
    COMMAND
      "${BASH_EXECUTABLE}"
      "-c"
      "printf '%s\n' \"$1\"; exit 77"
      "waterwall-skip"
      "${skip_message}"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 120
      SKIP_RETURN_CODE 77
  )
  add_waterwall_test_labels(${test_name} "integration" "tunnels")
endfunction()
function(add_waterwall_expected_failure_integration_test test_name case_name expected_output)
  set(case_dir "${WATERWALL_TEST_SOURCE_ROOT}/cases/${case_name}")
  if(ARGC GREATER 3)
    set(expected_status "${ARGV3}")
  else()
    set(expected_status "1")
  endif()

  add_waterwall_isolated_test(
    ${test_name}
    "${BASH_EXECUTABLE}"
    "${WATERWALL_TEST_SOURCE_ROOT}/run_waterwall_expected_failure_case.sh"
    "${WATERWALL_TEST_SOURCE_ROOT}/run_waterwall_case.sh"
    "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
    "${case_dir}"
    "10"
    "${expected_output}"
    "${expected_status}"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 120
  )
  add_waterwall_test_labels(${test_name} "integration" "tunnels" "negative")
  add_waterwall_case_resource_lock(${test_name} ${case_name})
endfunction()
function(add_waterwall_probe_integration_test test_name case_name timeout_seconds)
  set(case_dir "${WATERWALL_TEST_SOURCE_ROOT}/cases/${case_name}")

  add_waterwall_isolated_test(
    ${test_name}
    "${BASH_EXECUTABLE}"
    "${WATERWALL_TEST_SOURCE_ROOT}/run_waterwall_probe_case.sh"
    "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
    "${case_dir}"
    "${timeout_seconds}"
    "${PYTHON3_EXECUTABLE}"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 120
  )
  add_waterwall_test_labels(${test_name} "integration" "tunnels" "probe")
  add_waterwall_case_resource_lock(${test_name} ${case_name})
endfunction()
function(add_waterwall_privileged_probe_integration_test test_name case_name timeout_seconds)
  set(case_dir "${WATERWALL_TEST_SOURCE_ROOT}/cases/${case_name}")

  if(WATERWALL_ENABLE_PRIVILEGED_INTEGRATION_TESTS)
    add_waterwall_isolated_test(
      ${test_name}
      "${BASH_EXECUTABLE}"
      "${WATERWALL_TEST_SOURCE_ROOT}/run_waterwall_privileged_probe_case.sh"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
      "${case_dir}"
      "${timeout_seconds}"
      "${PYTHON3_EXECUTABLE}"
    )

    set_tests_properties(
      ${test_name}
      PROPERTIES
        TIMEOUT 120
        SKIP_RETURN_CODE 77
    )
    add_waterwall_test_labels(${test_name} "integration" "tunnels" "probe" "privileged" "socket-manager")
    add_waterwall_case_resource_lock(${test_name} ${case_name})
  else()
    add_waterwall_skipped_integration_test(
      ${test_name}
      "privileged integration tests disabled; configure with -DWATERWALL_ENABLE_PRIVILEGED_INTEGRATION_TESTS=ON"
    )
    add_waterwall_test_labels(${test_name} "integration" "tunnels" "probe" "privileged" "socket-manager")
  endif()
endfunction()
function(add_waterwall_iptables_recovery_integration_test test_name)
  if(WATERWALL_ENABLE_PRIVILEGED_INTEGRATION_TESTS AND LINUX)
    add_test(
      NAME ${test_name}
      COMMAND
        "${BASH_EXECUTABLE}"
        "${WATERWALL_TEST_SOURCE_ROOT}/run_iptables_crash_recovery_test.sh"
        "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
        "${PYTHON3_EXECUTABLE}"
    )
    set_tests_properties(
      ${test_name}
      PROPERTIES
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        RESOURCE_LOCK waterwall_iptables_recovery
    )
    add_waterwall_test_labels(${test_name} "integration" "linux" "privileged" "socket-manager" "iptables" "self-managed-network-namespace" "host-network")
  else()
    add_waterwall_skipped_integration_test(
      ${test_name}
      "iptables crash-recovery integration requires enabled Linux privileged tests"
    )
    add_waterwall_test_labels(${test_name} "integration" "linux" "privileged" "socket-manager" "iptables")
  endif()
endfunction()
function(add_waterwall_packet_analysis_test test_name case_name)
  set(case_dir "${WATERWALL_TEST_SOURCE_ROOT}/cases/${case_name}")

  add_waterwall_isolated_test(
    ${test_name}
    "${BASH_EXECUTABLE}"
    "${WATERWALL_TEST_SOURCE_ROOT}/run_packet_analysis_case.sh"
    "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
    "${case_dir}"
    "30"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 120
  )
  add_waterwall_test_labels(${test_name} "integration" "tunnels" "packet-analysis")
  add_waterwall_case_resource_lock(${test_name} ${case_name})
endfunction()
function(add_waterwall_speedtest test_name speedtest_name)
  set(speedtest_dir "${WATERWALL_TEST_SOURCE_ROOT}/speedtests/${speedtest_name}")

  add_waterwall_isolated_test(
    ${test_name}
    "${BASH_EXECUTABLE}"
    "${WATERWALL_TEST_SOURCE_ROOT}/run_waterwall_speedtest.sh"
    "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
    "${speedtest_dir}"
    "45"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 120
      RUN_SERIAL TRUE
  )
  add_waterwall_test_labels(${test_name} "integration" "tunnels" "speedtest")
  add_waterwall_case_resource_lock(${test_name} "speedtest_${speedtest_name}")
endfunction()
function(add_waterwall_external_speedtest test_name speedtest_name)
  set(speedtest_dir "${WATERWALL_TEST_SOURCE_ROOT}/speedtests/${speedtest_name}")

  add_test(
    NAME ${test_name}
    COMMAND
      "${BASH_EXECUTABLE}"
      "${WATERWALL_TEST_SOURCE_ROOT}/run_waterwall_speedtest.sh"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
      "${speedtest_dir}"
      "45"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 120
      RUN_SERIAL TRUE
  )
  add_waterwall_test_labels(${test_name} "integration" "tunnels" "speedtest" "external-network" "host-network")
  add_waterwall_case_resource_lock(${test_name} "speedtest_${speedtest_name}")
endfunction()
