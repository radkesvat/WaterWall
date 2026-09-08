if(NOT TARGET TunDevice OR NOT (CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64"))
  return()
endif()

add_executable(windows_driver_artifacts_test
  "${PROJECT_SOURCE_DIR}/tests/unittests/windows_driver_artifacts_test.c")
target_include_directories(windows_driver_artifacts_test PRIVATE "${PROJECT_SOURCE_DIR}/ww"
  "${PROJECT_SOURCE_DIR}/tunnels/TunDevice/include/TunDevice")
target_link_libraries(windows_driver_artifacts_test PRIVATE TunDevice ww advapi32)
set_target_properties(windows_driver_artifacts_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
add_test(NAME waterwall.windows_driver_artifacts_unit COMMAND windows_driver_artifacts_test)
set_tests_properties(waterwall.windows_driver_artifacts_unit PROPERTIES TIMEOUT 30 LABELS "unit;devices;windows;security")
if(TARGET waterwall_platform_unit_tests)
  add_dependencies(waterwall_platform_unit_tests windows_driver_artifacts_test)
endif()
