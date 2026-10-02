# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
waterwall_add_native_executable(core_configuration_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/core/core_configuration_test.c
  ${CMAKE_SOURCE_DIR}/core/core_settings.c
  ${CMAKE_SOURCE_DIR}/core/imported_tunnels.c
  ${CMAKE_SOURCE_DIR}/core/os_helpers.c
  ${CMAKE_SOURCE_DIR}/core/startup_options.c)
  target_link_libraries(core_configuration_test PRIVATE ww_test_support)
target_include_directories(core_configuration_test PRIVATE ${CMAKE_SOURCE_DIR}/core)
target_link_libraries(core_configuration_test PRIVATE ww)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_options(core_configuration_test PRIVATE "LINKER:--wrap=get_nprocs" "LINKER:--wrap=sysconf")
endif()
add_dependencies(waterwall_unit_tests core_configuration_test)
add_waterwall_unit_test(
  waterwall.core_configuration_unit
  core_configuration_test
  "unit;core;configuration"
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING AND
    CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64)$")
  waterwall_add_native_executable(packed_startup_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/core/packed_startup_test.c
    ${CMAKE_SOURCE_DIR}/core/launcher/main.c
    ${CMAKE_SOURCE_DIR}/core/launcher/launcher_linux.c
    ${CMAKE_SOURCE_DIR}/core/startup_options.c
    ${CMAKE_SOURCE_DIR}/ww/node_builder/config_lexical.c
    ${CMAKE_SOURCE_DIR}/ww/vendor/cjson/cJSON.c)
  target_link_libraries(packed_startup_test PRIVATE ww_test_support)
  target_include_directories(packed_startup_test PRIVATE
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/core/launcher
    ${CMAKE_SOURCE_DIR}/ww/node_builder
    ${CMAKE_SOURCE_DIR}/ww/compression/include
    ${CMAKE_SOURCE_DIR}/ww/vendor/xz-embedded/include
    ${CMAKE_SOURCE_DIR}/ww/vendor/cjson
    ${CMAKE_BINARY_DIR}/ww
  )
  target_compile_definitions(packed_startup_test PRIVATE
    WW_CJSON_CRT_ALLOCATOR=1
    WATERWALL_HAS_STARTUP_GUARD=1
    WATERWALL_VERSION=${Waterwall_VERSION}
  )
  set_target_properties(packed_startup_test PROPERTIES
    UNITY_BUILD OFF
    DISABLE_PRECOMPILE_HEADERS ON
    LINKER_LANGUAGE C
  )
  foreach(symbol IN ITEMS syscall ftruncate mmap munmap fcntl close write lseek)
    target_link_options(packed_startup_test PRIVATE "LINKER:--wrap=${symbol}")
  endforeach()
  target_link_libraries(packed_startup_test PRIVATE pthread rt m)
  add_dependencies(waterwall_unit_tests packed_startup_test)
  add_waterwall_unit_test(
    waterwall.packed_startup_unit
    packed_startup_test
    "unit;core;launcher;packed;linux"
  )
endif()


# Tunnel hard-abort runtime cases. The registration is shared with the native
# Windows/macOS test configurations, which do not add the tests/ subtree.
