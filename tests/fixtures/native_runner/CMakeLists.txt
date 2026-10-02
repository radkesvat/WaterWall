cmake_minimum_required(VERSION 3.20)
project(WaterWallNativeRunnerFixture C)
include(CTest)
add_executable(runner_fixture fixture.c)
target_compile_definitions(runner_fixture PRIVATE
  FIXTURE_CONFIG="$<CONFIG>" FIXTURE_VALUE="${FIXTURE_VALUE}"
  FIXTURE_ACTIVE_FILE="${CMAKE_BINARY_DIR}/child-active")
# Every auto-build checks that no cooperating runner is executing this target.
add_custom_target(build_guard
  COMMAND "${CMAKE_COMMAND}" "-DACTIVE_FILE=${CMAKE_BINARY_DIR}/child-active" -P "${CMAKE_CURRENT_SOURCE_DIR}/build_guard.cmake")
add_dependencies(runner_fixture build_guard)
add_custom_target(build_failure COMMAND "${CMAKE_COMMAND}" -E false)
add_custom_target(build_timeout COMMAND "${CMAKE_COMMAND}" -E sleep 3)
file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/executable-$<CONFIG>.txt" CONTENT "$<TARGET_FILE:runner_fixture>")
foreach(test_name IN ITEMS fixture_pass fixture_build_failure)
  set(target runner_fixture)
  if(test_name STREQUAL fixture_build_failure)
    set(target build_failure)
  endif()
  add_test(NAME ${test_name} COMMAND "${CMAKE_COMMAND}"
    "-DUNIT_TEST_TARGET=${target}" "-DUNIT_TEST_EXECUTABLE=$<TARGET_FILE:runner_fixture>"
    "-DUNIT_TEST_BUILD_DIR=${CMAKE_BINARY_DIR}" "-DUNIT_TEST_CONFIG=$<CONFIG>"
    "-DUNIT_TEST_NAME=waterwall.runner_fixture"
    "-DUNIT_TEST_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
    "-DUNIT_TEST_FIXTURE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
    "-DUNIT_TEST_ARGUMENTS=pass;ctest" -P "${RUNNER}")
  set_tests_properties(${test_name} PROPERTIES TIMEOUT 215)
endforeach()
