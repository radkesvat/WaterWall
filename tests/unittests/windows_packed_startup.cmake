# Reused by native platform units and the standalone MinGW backend fixture.
add_executable(windows_packed_startup_test
  "${WATERWALL_SOURCE_DIR}/tests/unittests/windows_packed_startup_test.c"
  "${WATERWALL_SOURCE_DIR}/core/startup_options.c"
  "${WATERWALL_SOURCE_DIR}/ww/node_builder/config_lexical.c"
  "${WATERWALL_SOURCE_DIR}/ww/vendor/cjson/cJSON.c")
target_compile_definitions(windows_packed_startup_test PRIVATE _WIN32_WINNT=0x0600 WW_CJSON_CRT_ALLOCATOR=1)
target_include_directories(windows_packed_startup_test PRIVATE
  "${WATERWALL_SOURCE_DIR}/core" "${WATERWALL_SOURCE_DIR}/ww/node_builder"
  "${WATERWALL_SOURCE_DIR}/ww/vendor/cjson")
set_target_properties(windows_packed_startup_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
add_test(NAME waterwall.windows_packed_startup_unit COMMAND windows_packed_startup_test)
set_tests_properties(waterwall.windows_packed_startup_unit PROPERTIES TIMEOUT 30 LABELS "unit;core;launcher;windows")
if(TARGET waterwall_platform_unit_tests)
  add_dependencies(waterwall_platform_unit_tests windows_packed_startup_test)
endif()

add_executable(windows_launcher_arguments_test
  "${WATERWALL_SOURCE_DIR}/tests/unittests/windows_launcher_arguments_test.c"
  "${WATERWALL_SOURCE_DIR}/core/launcher/session_windows.c"
  "${WATERWALL_SOURCE_DIR}/core/lifecycle_capabilities_windows.c")
target_compile_definitions(windows_launcher_arguments_test PRIVATE _WIN32_WINNT=0x0600)
target_include_directories(windows_launcher_arguments_test PRIVATE "${WATERWALL_SOURCE_DIR}/core")
target_link_libraries(windows_launcher_arguments_test PRIVATE WaterWall::XZDecoder shell32 iphlpapi)
set_target_properties(windows_launcher_arguments_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
add_test(NAME waterwall.windows_launcher_arguments_unit COMMAND windows_launcher_arguments_test)
set_tests_properties(waterwall.windows_launcher_arguments_unit PROPERTIES TIMEOUT 30 LABELS "unit;core;launcher;windows")
if(TARGET waterwall_platform_unit_tests)
  add_dependencies(waterwall_platform_unit_tests windows_launcher_arguments_test)
endif()
