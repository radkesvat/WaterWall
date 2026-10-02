# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
include("${WATERWALL_UNIT_SOURCE_ROOT}/tunnels_abort_runtime_test.cmake")

add_custom_target(check_waterwall_unit_tests
  COMMAND
    "${CMAKE_CTEST_COMMAND}"
    --test-dir "${CMAKE_BINARY_DIR}"
    -C "$<CONFIG>"
    --output-on-failure
    -L unit
  DEPENDS waterwall_unit_tests
  USES_TERMINAL
)

