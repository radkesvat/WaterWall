# Explicit integration registrations; preserve namespace and family variants.
add_test(
  NAME waterwall.application_shutdown_authority_policy
  COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/application_shutdown_authority_policy_test.py"
)
set_tests_properties(waterwall.application_shutdown_authority_policy PROPERTIES LABELS "unit;policy;core;lifecycle;shutdown")

add_test(
  NAME waterwall.device_reader_retire_order_policy
  COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/device_reader_retire_order_policy_test.py"
)
set_tests_properties(waterwall.device_reader_retire_order_policy PROPERTIES LABELS "unit;policy;devices;lifetime;fragments")

add_test(
  NAME waterwall.udpstatelesssocket_io_owner_policy
  COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/udpstatelesssocket_io_owner_policy_test.py"
)
set_tests_properties(waterwall.udpstatelesssocket_io_owner_policy PROPERTIES LABELS "unit;policy;tunnels;udpstatelesssocket;worker;ownership")

# Helper to append labels to a test without overwriting existing labels.

# Every runner now copies its case directory into a private run directory, so
# generated files can no longer collide. The listener ports inside config.json
# are still a shared resource though: distinct cases pick distinct ports, but
# several tests may point at the same case directory. Locking on the case name
# keeps those siblings off each other's ports under `ctest -j` while unrelated
# cases stay fully parallel.









add_test(
  NAME waterwall.expected_failure_runner
  COMMAND
    "${BASH_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_waterwall_expected_failure_case_test.sh"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_waterwall_expected_failure_case.sh"
)
set_tests_properties(
  waterwall.expected_failure_runner
  PROPERTIES
    TIMEOUT 10
    LABELS "test-harness;negative"
)

# The regression configures its own small project and never builds this tree.
add_test(NAME waterwall.native_runner
  COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/native_runner_test.py"
    --build-dir "${CMAKE_BINARY_DIR}" --cmake "${CMAKE_COMMAND}"
    --ctest "${CMAKE_CTEST_COMMAND}" --compiler "${CMAKE_C_COMPILER}")
set_tests_properties(waterwall.native_runner PROPERTIES
  TIMEOUT 120 LABELS "unit;test-harness;build")

add_test(NAME waterwall.python_test_support
  COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/support/python/support_test.py"
    --build-dir "${CMAKE_BINARY_DIR}")
set_tests_properties(waterwall.python_test_support PROPERTIES
  TIMEOUT 45 LABELS "unit;test-harness")

add_test(
  NAME waterwall.test_runner_edge_cases
  COMMAND
    "${BASH_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/test_runner_edge_cases_test.sh"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_waterwall_case.sh"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_waterwall_speedtest.sh"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_waterwall_probe_case.sh"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_packet_analysis_case.sh"
    "${CMAKE_CURRENT_SOURCE_DIR}/case_run_dir.lib.sh"
)
set_tests_properties(
  waterwall.test_runner_edge_cases
  PROPERTIES
    TIMEOUT 15
    LABELS "test-harness"
)

if(LINUX AND WATERWALL_ENABLE_INTEGRATION_TEST_NETNS)
  add_test(
    NAME waterwall.network_namespace_wrapper
    COMMAND
      "${BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/run_in_network_namespace_test.sh"
      "${CMAKE_CURRENT_SOURCE_DIR}/run_in_network_namespace.sh"
      "${PYTHON3_EXECUTABLE}"
  )
  set_tests_properties(
    waterwall.network_namespace_wrapper
    PROPERTIES
      TIMEOUT 30
      LABELS "test-harness;linux;netns"
  )
endif()

if(LINUX)
  add_test(
    NAME waterwall.test_lane_runner
    COMMAND
      "${BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/run_test_lane_test.sh"
      "${CMAKE_CURRENT_SOURCE_DIR}/run_test_lane.sh"
  )
  set_tests_properties(
    waterwall.test_lane_runner
    PROPERTIES
      TIMEOUT 30
      LABELS "test-harness;linux"
  )
endif()

add_test(
  NAME waterwall.lwip_shutdown_order_policy
  COMMAND
    "${PYTHON3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/lwip_shutdown_order_policy_test.py"
)
set_tests_properties(
  waterwall.lwip_shutdown_order_policy
  PROPERTIES
    TIMEOUT 10
    LABELS "unit;net;lwip;lifetime;shutdown;policy"
)







