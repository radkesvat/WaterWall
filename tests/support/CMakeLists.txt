add_subdirectory(c)

add_executable(test_support_regression c/support_regression.c c/support_regression_aux.c)
target_compile_definitions(test_support_regression PRIVATE NDEBUG=1)
target_link_libraries(test_support_regression PRIVATE ww_test_support)
set_target_properties(test_support_regression PROPERTIES
  DISABLE_PRECOMPILE_HEADERS ON INTERPROCEDURAL_OPTIMIZATION OFF UNITY_BUILD OFF)
add_library(test_support_cpp_header OBJECT c/support_cpp_header.cpp)
target_link_libraries(test_support_cpp_header PRIVATE ww_test_support)
set_target_properties(test_support_cpp_header PROPERTIES
  DISABLE_PRECOMPILE_HEADERS ON INTERPROCEDURAL_OPTIMIZATION OFF)
add_dependencies(test_support_regression test_support_cpp_header)

add_test(NAME waterwall.test_support_unit
  COMMAND "${CMAKE_COMMAND}"
    "-DSUPPORT_EXECUTABLE=$<TARGET_FILE:test_support_regression>"
    "-DSUPPORT_BUILD_DIR=${CMAKE_BINARY_DIR}"
    "-DSUPPORT_CONFIG=$<CONFIG>"
    "-DSUPPORT_SOURCE_DIR=${CMAKE_SOURCE_DIR}"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/run_support_regression.cmake")
set_tests_properties(waterwall.test_support_unit PROPERTIES
  TIMEOUT 155 LABELS "unit;test-harness;portable" RESOURCE_LOCK waterwall_unit_test_build)
if(TARGET waterwall_platform_unit_tests)
  add_dependencies(waterwall_platform_unit_tests test_support_regression)
endif()
