# Registers waterwall.tundevice_policy_cleanup_unit: the real policy-cleanup
# fixture and ww retain their explicit platform registration and isolated runner.
include("${CMAKE_CURRENT_LIST_DIR}/../cmake/TestHelpers.cmake")
waterwall_add_native_executable(tundevice_policy_cleanup_test SUPPORT EXCLUDE_FROM_ALL SOURCES "${PROJECT_SOURCE_DIR}/tests/unittests/devices/tundevice_policy_cleanup_test.c")
  target_link_libraries(tundevice_policy_cleanup_test PRIVATE ww_test_support)
target_include_directories(tundevice_policy_cleanup_test PRIVATE
  "${PROJECT_SOURCE_DIR}/tunnels/TunDevice/include/TunDevice")
target_link_libraries(tundevice_policy_cleanup_test PRIVATE ww)
set_target_properties(tundevice_policy_cleanup_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
add_test(NAME waterwall.tundevice_policy_cleanup_unit
    COMMAND "${CMAKE_COMMAND}"
      "-DUNIT_TEST_TARGET=tundevice_policy_cleanup_test"
      "-DUNIT_TEST_EXECUTABLE=$<TARGET_FILE:tundevice_policy_cleanup_test>"
      "-DUNIT_TEST_BUILD_DIR=${CMAKE_BINARY_DIR}"
      "-DUNIT_TEST_CONFIG=$<CONFIG>"
      "-DUNIT_TEST_NAME=waterwall.tundevice_policy_cleanup_unit"
      "-DUNIT_TEST_SOURCE_DIR=${PROJECT_SOURCE_DIR}"
      "-DUNIT_TEST_FIXTURE_DIR=${PROJECT_SOURCE_DIR}/tests/unittests/fixtures"
      "-DUNIT_TEST_TIMEOUT=30"
      -P "${PROJECT_SOURCE_DIR}/tests/unittests/run_unit_test.cmake")
set_tests_properties(waterwall.tundevice_policy_cleanup_unit PROPERTIES TIMEOUT 125 RESOURCE_LOCK waterwall_unit_test_build LABELS "unit;tunnels;windows;shutdown")
waterwall_register_platform_native_unit(waterwall.tundevice_policy_cleanup_unit tundevice_policy_cleanup_test
  "unit;tunnels;windows;shutdown")
