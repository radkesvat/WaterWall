# Shared registration mechanics. Source roots are captured here, independent of
# the directory that includes a fragment or calls a function. Specialized seams,
# source substitutions, wrappers, variants and verdicts remain in registrations.
include_guard(GLOBAL)
get_filename_component(WATERWALL_TEST_SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(WATERWALL_UNIT_SOURCE_ROOT "${WATERWALL_TEST_SOURCE_ROOT}/unittests")
set(WATERWALL_TEST_SUPPORT_ROOT "${WATERWALL_TEST_SOURCE_ROOT}/support")
set(WATERWALL_UNIT_TEST_RUNNER "${WATERWALL_UNIT_SOURCE_ROOT}/run_unit_test.cmake")

# Attach a target once to the selected aggregate, including existing targets.
function(waterwall_native_aggregate target_name aggregate)
  if(NOT TARGET ${target_name} OR NOT TARGET ${aggregate})
    message(FATAL_ERROR "Missing native target/aggregate: ${target_name}/${aggregate}")
  endif()
  get_target_property(members ${aggregate} MANUALLY_ADDED_DEPENDENCIES)
  if(NOT target_name IN_LIST members)
    add_dependencies(${aggregate} ${target_name})
  endif()
endfunction()

# Ordinary creation only: keep exceptional link options and properties beside
# their targets. Support linkage is opt-in so standalone link probes stay pure.
function(waterwall_add_native_executable target_name)
  cmake_parse_arguments(TEST "EXCLUDE_FROM_ALL;SUPPORT" "" "SOURCES;INCLUDES;LIBRARIES;DEFINITIONS" ${ARGN})
  if(TEST_UNPARSED_ARGUMENTS OR NOT TEST_SOURCES)
    message(FATAL_ERROR "Invalid native executable arguments: ${target_name}")
  endif()
  if(TEST_EXCLUDE_FROM_ALL)
    add_executable(${target_name} EXCLUDE_FROM_ALL ${TEST_SOURCES})
  else()
    add_executable(${target_name} ${TEST_SOURCES})
  endif()
  if(TEST_INCLUDES)
    target_include_directories(${target_name} PRIVATE ${TEST_INCLUDES})
  endif()
  if(TEST_LIBRARIES)
    target_link_libraries(${target_name} PRIVATE ${TEST_LIBRARIES})
  endif()
  if(TEST_DEFINITIONS)
    target_compile_definitions(${target_name} PRIVATE ${TEST_DEFINITIONS})
  endif()
  if(TEST_SUPPORT)
    target_link_libraries(${target_name} PRIVATE ww_test_support)
  endif()
endfunction()

# Existing-target registration keeps the accepted portable CMake runner and its
# exact lock/build/execution budgets. The fixture root is independent of CWD.
function(waterwall_register_native_test test_name target_name labels)
  cmake_parse_arguments(TEST "" "TIMEOUT;AGGREGATE;SOURCE_DIR" "" ${ARGN})
  if(TEST_UNPARSED_ARGUMENTS)
    message(FATAL_ERROR "Invalid native registration arguments: ${test_name}")
  endif()
  if(NOT TEST_SOURCE_DIR)
    set(TEST_SOURCE_DIR "${CMAKE_SOURCE_DIR}")
  endif()
  if(NOT TEST_TIMEOUT)
    set(TEST_TIMEOUT 120)
  endif()
  math(EXPR outer_timeout "${TEST_TIMEOUT} + 95")
  add_test(NAME ${test_name} COMMAND "${CMAKE_COMMAND}"
    "-DUNIT_TEST_TARGET=${target_name}"
    "-DUNIT_TEST_CONFIG=$<CONFIG>"
    "-DUNIT_TEST_EXECUTABLE=$<TARGET_FILE:${target_name}>"
    "-DUNIT_TEST_BUILD_DIR=${CMAKE_BINARY_DIR}"
    "-DUNIT_TEST_NAME=${test_name}"
    "-DUNIT_TEST_SOURCE_DIR=${TEST_SOURCE_DIR}"
    "-DUNIT_TEST_FIXTURE_DIR=${WATERWALL_UNIT_SOURCE_ROOT}/fixtures"
    "-DUNIT_TEST_TIMEOUT=${TEST_TIMEOUT}"
    -P "${WATERWALL_UNIT_TEST_RUNNER}")
  set_tests_properties(${test_name} PROPERTIES TIMEOUT "${outer_timeout}"
    LABELS "${labels}" RESOURCE_LOCK waterwall_unit_test_build)
  if(TEST_AGGREGATE)
    waterwall_native_aggregate(${target_name} ${TEST_AGGREGATE})
  endif()
endfunction()

# Preserve the Linux registration's established positional call interface.
function(add_waterwall_unit_test test_name target_name labels)
  set(execution_timeout 120)
  if(ARGC GREATER 3)
    set(execution_timeout "${ARGV3}")
  endif()
  waterwall_register_native_test(${test_name} ${target_name} "${labels}"
    TIMEOUT ${execution_timeout} AGGREGATE waterwall_unit_tests)
endfunction()
