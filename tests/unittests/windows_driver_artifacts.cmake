# Registers waterwall.windows_driver_artifacts_unit from the real Windows driver
# fixture. The x64 TunDevice prerequisite and native/platform aggregate remain
# explicit; common registration supplies isolated build/run and the build lock.
include("${CMAKE_CURRENT_LIST_DIR}/../cmake/TestHelpers.cmake")
if(NOT TARGET TunDevice OR NOT (CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64"))
  return()
endif()

waterwall_add_native_executable(windows_driver_artifacts_test SUPPORT SOURCES "${PROJECT_SOURCE_DIR}/tests/unittests/core/windows_driver_artifacts_test.c")
target_include_directories(windows_driver_artifacts_test PRIVATE "${PROJECT_SOURCE_DIR}/ww"
  "${PROJECT_SOURCE_DIR}/tunnels/TunDevice/include/TunDevice")
target_link_libraries(windows_driver_artifacts_test PRIVATE TunDevice ww advapi32)
set_target_properties(windows_driver_artifacts_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
waterwall_register_native_test(waterwall.windows_driver_artifacts_unit windows_driver_artifacts_test
  "unit;devices;windows;security" TIMEOUT 30 SOURCE_DIR "${PROJECT_SOURCE_DIR}")
if(TARGET waterwall_platform_unit_tests)
  waterwall_native_aggregate(windows_driver_artifacts_test waterwall_platform_unit_tests)
endif()
