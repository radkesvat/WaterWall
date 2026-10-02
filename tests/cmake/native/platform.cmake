# Root/platform registrations, including standalone archive and Windows seams.
# A direct consumer verifies that XZ needs neither ww nor its public headers.
if(BUILD_TESTING AND WW_BUILD_UNIT_TESTS)
  waterwall_add_native_executable(xz_embedded_test SOURCES tests/unittests/base/xz_embedded_test.c)
  target_link_libraries(xz_embedded_test PRIVATE XZEmbedded::XZEmbedded)
  set_target_properties(xz_embedded_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON)
  waterwall_register_native_test(waterwall.xz_embedded_unit xz_embedded_test "unit;vendor;xz;portable" TIMEOUT 30)
  if(TARGET waterwall_unit_tests)
    add_dependencies(waterwall_unit_tests xz_embedded_test)
  elseif(TARGET waterwall_platform_unit_tests)
    add_dependencies(waterwall_platform_unit_tests xz_embedded_test)
  endif()
endif()

# Windows does not add the tests/ subtree, so register the focused interface-name
# test here as well. The test remains build-on-demand through its CTest runner.
if(BUILD_TESTING AND WW_BUILD_UNIT_TESTS AND WIN32)
  set(WATERWALL_SOURCE_DIR "${PROJECT_SOURCE_DIR}")
  include("${PROJECT_SOURCE_DIR}/tests/unittests/windows_packed_startup.cmake")
  include("${PROJECT_SOURCE_DIR}/tests/unittests/windows_driver_artifacts.cmake")
  include("${PROJECT_SOURCE_DIR}/tests/unittests/tundevice_policy_cleanup.cmake")
  waterwall_add_native_executable(tun_windows_dns_test SUPPORT SOURCES tests/unittests/devices/tun_windows_dns_test.c)
  target_include_directories(tun_windows_dns_test PRIVATE "${PROJECT_SOURCE_DIR}/ww/devices/tun")
  set_target_properties(tun_windows_dns_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
  waterwall_register_native_test(waterwall.tun_windows_dns_unit tun_windows_dns_test "unit;devices;windows;dns" TIMEOUT 30)
  if(TARGET waterwall_platform_unit_tests)
    add_dependencies(waterwall_platform_unit_tests tun_windows_dns_test)
  endif()
  waterwall_add_native_executable(tun_windows_dns_identity_test SUPPORT SOURCES tests/unittests/devices/tun_windows_dns_identity_test.c)
  target_include_directories(tun_windows_dns_identity_test PRIVATE
    "${PROJECT_SOURCE_DIR}/ww/devices/tun" "${PROJECT_SOURCE_DIR}/ww/vendor/wintun")
  target_link_libraries(tun_windows_dns_identity_test PRIVATE ww)
  if(MINGW)
    target_link_options(tun_windows_dns_identity_test PRIVATE -static)
    target_link_options(tundevice_policy_cleanup_test PRIVATE -static)
  endif()
  set_target_properties(tun_windows_dns_identity_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
  waterwall_register_native_test(waterwall.tun_windows_dns_identity_unit tun_windows_dns_identity_test "unit;devices;windows;dns;identity" TIMEOUT 30)
  if(TARGET waterwall_platform_unit_tests)
    add_dependencies(waterwall_platform_unit_tests tun_windows_dns_identity_test)
  endif()
  waterwall_add_native_executable(windows_lifecycle_test SUPPORT EXCLUDE_FROM_ALL SOURCES tests/unittests/core/windows_lifecycle_test.c
    core/lifecycle_windows.c
    core/lifecycle_capabilities_windows.c
    core/startup_options.c)
  target_include_directories(windows_lifecycle_test PRIVATE "${PROJECT_SOURCE_DIR}/core")
  target_compile_definitions(windows_lifecycle_test PRIVATE WATERWALL_LIFECYCLE_TEST_HOOKS=1)
  target_link_libraries(windows_lifecycle_test PRIVATE ww)
  if(MINGW)
    target_link_options(windows_lifecycle_test PRIVATE -static)
  endif()
  set_target_properties(windows_lifecycle_test PROPERTIES
    DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF INTERPROCEDURAL_OPTIMIZATION OFF)
  waterwall_register_native_test(waterwall.windows_lifecycle_unit windows_lifecycle_test "unit;core;host;shutdown;windows" TIMEOUT 120)
  waterwall_register_platform_native_unit(waterwall.windows_lifecycle_unit windows_lifecycle_test
    "unit;core;host;shutdown;windows")
  target_compile_definitions(ww PUBLIC SIGNAL_MANAGER_TEST_HOOKS=1)
  waterwall_add_native_executable(windows_console_shutdown_test SUPPORT EXCLUDE_FROM_ALL SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/tests/unittests/core/windows_console_shutdown_test.c)
  set_target_properties(windows_console_shutdown_test PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION OFF
    INTERPROCEDURAL_OPTIMIZATION_DEBUG OFF
    INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO OFF
    INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL OFF
  )
  target_compile_definitions(windows_console_shutdown_test PRIVATE SIGNAL_MANAGER_TEST_HOOKS=1)
  target_link_libraries(windows_console_shutdown_test PRIVATE ww)
  waterwall_register_native_test(waterwall.windows_console_shutdown_unit windows_console_shutdown_test "unit;signal-manager;shutdown;windows" TIMEOUT 120)
  waterwall_register_platform_native_unit(
    waterwall.windows_console_shutdown_unit
    windows_console_shutdown_test
    "unit;signal-manager;shutdown;windows")

  waterwall_add_native_executable(wtime_epoch_test SUPPORT EXCLUDE_FROM_ALL SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/tests/unittests/base/wtime_epoch_test.c)
  set_target_properties(wtime_epoch_test PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION OFF
    INTERPROCEDURAL_OPTIMIZATION_DEBUG OFF
    INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO OFF
    INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL OFF
  )
  target_link_libraries(wtime_epoch_test PRIVATE ww)
  waterwall_register_native_test(waterwall.wtime_epoch_unit wtime_epoch_test "unit;libc;time;epoch;overflow;windows" TIMEOUT 120)
  waterwall_register_platform_native_unit(
    waterwall.wtime_epoch_unit wtime_epoch_test "unit;libc;time;epoch;overflow;windows")

  waterwall_add_native_executable(wsocket_windows_interface_test SUPPORT EXCLUDE_FROM_ALL SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/tests/unittests/net/wsocket_windows_interface_test.c)
  set_target_properties(wsocket_windows_interface_test PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION OFF
    INTERPROCEDURAL_OPTIMIZATION_DEBUG OFF
    INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO OFF
    INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL OFF
  )
  target_link_libraries(wsocket_windows_interface_test PRIVATE ww)
  waterwall_register_native_test(waterwall.wsocket_windows_interface_unit wsocket_windows_interface_test "unit;net;socket;windows;interface" TIMEOUT 120)
  waterwall_register_platform_native_unit(
    waterwall.wsocket_windows_interface_unit wsocket_windows_interface_test "unit;net;socket;windows;interface")
endif()

# Native-IOCP-only tests. The Linux tests/ subdirectory is not added on Windows,
# so the native IOCP backend registers its own test executable here, and only
# when that backend is actually selected (windows-iocp preset).
if(BUILD_TESTING AND WW_BUILD_UNIT_TESTS AND WIN32 AND WITH_NATIVE_IOCP)
  # Narrow AcceptEx fault-injection seam. PUBLIC so the ww static library and the
  # test executable agree on the declaration; it stays out of production builds
  # because this block only runs for a testing-enabled native IOCP configuration.
  target_compile_definitions(ww PUBLIC WATERWALL_IOCP_TEST_HOOKS=1)

  waterwall_add_native_executable(iocp_native_test SUPPORT EXCLUDE_FROM_ALL SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/tests/unittests/net/event/iocp_native_test.c)
  set_target_properties(iocp_native_test PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION OFF
    INTERPROCEDURAL_OPTIMIZATION_DEBUG OFF
    INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO OFF
    INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL OFF
  )
  target_link_libraries(iocp_native_test PRIVATE ww ws2_32 mswsock)
  waterwall_register_native_test(waterwall.iocp_native iocp_native_test "unit;net;iocp;windows;native" TIMEOUT 120)
  waterwall_register_platform_native_unit(
    waterwall.iocp_native iocp_native_test "unit;net;iocp;windows;native")
endif()

if(TARGET waterwall_platform_unit_tests AND WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 8)
  # Compile the actual reader session with pointer-width Windows atomics even
  # when the compiler normally selects C11. Never link this diagnostic object
  # into the runtime, whose atomic representation may differ.
  add_library(device_reader_session_windows_fallback_compile OBJECT EXCLUDE_FROM_ALL
    tests/unittests/devices/device_reader_session_windows_fallback_compile.c
    ww/devices/device_reader_session.c
    ww/devices/device_reader_budget.c
    ww/devices/device_reader_dispatch.c)
  target_link_libraries(device_reader_session_windows_fallback_compile PRIVATE ww)
  target_compile_definitions(device_reader_session_windows_fallback_compile PRIVATE WW_HAVE_C11_ATOMICS=0)
  set_target_properties(device_reader_session_windows_fallback_compile PROPERTIES
    DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF INTERPROCEDURAL_OPTIMIZATION OFF)
  add_dependencies(waterwall_platform_unit_tests device_reader_session_windows_fallback_compile)
endif()

