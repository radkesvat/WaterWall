# GameNetworkingSockets keeps its own service thread and reads its own clock, so
# these tests run in real time. Only the stock-peer interop case uses UDP sockets.

# Under ThreadSanitizer the library's own lock is invisible (see the suppression
# file), so memory that the uninstrumented library touches through intercepted
# calls such as memcpy looks unprotected too. Those accesses are ignored; code
# that WaterWall compiles is instrumented and stays checked.
set(WATERWALL_GNS_TSAN_OPTIONS
  "halt_on_error=1:ignore_interceptors_accesses=1:suppressions=${CMAKE_SOURCE_DIR}/tests/gns_tsan_suppressions.txt")

if(TARGET WaterWall::Gns)
  waterwall_add_native_executable(gns_transport_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/gns/gns_transport_test.cc
    LIBRARIES WaterWall::Gns waterwall_cpu_options)
  target_compile_features(gns_transport_test PRIVATE cxx_std_20)
  set_target_properties(gns_transport_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
  add_waterwall_unit_test(waterwall.gns_transport_unit gns_transport_test "unit;tunnels;gns;transport;close" 180)
  set_property(TEST waterwall.gns_transport_unit APPEND PROPERTY
    ENVIRONMENT "TSAN_OPTIONS=${WATERWALL_GNS_TSAN_OPTIONS}")
  # The archive check needs plain object code; the unit tree builds without IPO.
  if(CMAKE_NM AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_dependencies(waterwall_unit_tests waterwall_gns)
    # A fresh tree builds the GNS dependencies and may have to bootstrap host protoc.
    set(gns_symbol_build_timeout 900)
    set(gns_symbol_scan_timeout 30)
    math(EXPR gns_symbol_outer_timeout "${gns_symbol_build_timeout} + ${gns_symbol_scan_timeout} + 35")
    # Resolve the archive path without making it a CTest prerequisite. The runner
    # builds it under the same lock as the other native tests.
    set(gns_symbol_scan_args
      "-DNM=${CMAKE_NM}"
      "-DGNS_ARCHIVE=$<TARGET_FILE_DIR:waterwall_gns>/$<TARGET_FILE_NAME:waterwall_gns>"
      -P "${WATERWALL_TEST_SOURCE_ROOT}/gns_no_os_socket_symbols.cmake")
    add_test(NAME waterwall.gns_no_os_socket_symbols
      COMMAND "${CMAKE_COMMAND}"
        "-DUNIT_TEST_TARGET=waterwall_gns"
        "-DUNIT_TEST_CONFIG=$<CONFIG>"
        "-DUNIT_TEST_EXECUTABLE=${CMAKE_COMMAND}"
        "-DUNIT_TEST_BUILD_DIR=${CMAKE_BINARY_DIR}"
        "-DUNIT_TEST_NAME=waterwall.gns_no_os_socket_symbols"
        "-DUNIT_TEST_SOURCE_DIR=${CMAKE_SOURCE_DIR}"
        "-DUNIT_TEST_FIXTURE_DIR=${WATERWALL_UNIT_SOURCE_ROOT}/fixtures"
        "-DUNIT_TEST_BUILD_TIMEOUT=${gns_symbol_build_timeout}"
        "-DUNIT_TEST_TIMEOUT=${gns_symbol_scan_timeout}"
        "-DUNIT_TEST_ARGUMENTS=${gns_symbol_scan_args}"
        -P "${WATERWALL_UNIT_TEST_RUNNER}")
    set_tests_properties(waterwall.gns_no_os_socket_symbols PROPERTIES
      TIMEOUT "${gns_symbol_outer_timeout}" RESOURCE_LOCK waterwall_unit_test_build
      LABELS "unit;policy;build;linking;gns")
  endif()
endif()

# The node layer uses the WaterWall API: settings, the port between the library's
# threads and a worker, and the engine calls on top of it.
if(TARGET GnsCommon)
  waterwall_add_native_executable(gns_settings_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/gns/gns_settings_test.c
            ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/gns/gns_test_logging.cc
    LIBRARIES GnsCommon ww WaterWall::Gns)
  add_waterwall_unit_test(waterwall.gns_settings_unit gns_settings_test "unit;tunnels;gns;settings")
  waterwall_add_native_executable(gns_port_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/gns/gns_port_test.c
    LIBRARIES GnsCommon ww)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(gns_port_test PRIVATE GNS_PORT_TEST_WRAP)
    target_link_options(gns_port_test PRIVATE
      "-Wl,--wrap=sendWorkerMessageForceQueueWithCleanup" "-Wl,--wrap=memoryFree")
  endif()
  add_waterwall_unit_test(waterwall.gns_port_unit gns_port_test "unit;tunnels;gns;port;engine;close" 180)
  set_property(TEST waterwall.gns_port_unit APPEND PROPERTY
    ENVIRONMENT "TSAN_OPTIONS=${WATERWALL_GNS_TSAN_OPTIONS}")
  waterwall_add_native_executable(gns_session_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/gns/gns_session_test.c
    LIBRARIES GnsCommon ww)
  add_waterwall_unit_test(waterwall.gns_session_unit gns_session_test
    "unit;tunnels;gns;session;pressure;close" 300)
  set_property(TEST waterwall.gns_session_unit APPEND PROPERTY
    ENVIRONMENT "TSAN_OPTIONS=${WATERWALL_GNS_TSAN_OPTIONS}")
  if(TARGET GnsClient AND TARGET GnsServer)
    waterwall_add_native_executable(gns_pair_test SUPPORT
      SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/gns/gns_pair_test.c
      LIBRARIES GnsClient GnsServer GnsCommon ww)
    add_waterwall_unit_test(waterwall.gns_pair_unit gns_pair_test
      "unit;tunnels;gns;line;close;pressure;lifecycle" 300)
    set_property(TEST waterwall.gns_pair_unit APPEND PROPERTY
      ENVIRONMENT "TSAN_OPTIONS=${WATERWALL_GNS_TSAN_OPTIONS}")
  endif()
  # The socket interop test runs a plain GameNetworkingSockets application in a
  # second process in the same private network namespace. It compiles upstream's own socket file, which
  # defines every low-level function the library calls, so the linker never
  # takes the external transport out of the archive: two definitions of those
  # functions would stop the link.
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    FetchContent_GetProperties(ww_gns)
    set(gns_socket_file
      "${ww_gns_SOURCE_DIR}/src/steamnetworkingsockets/clientlib/steamnetworkingsockets_socketthread.cpp")
    waterwall_add_native_executable(gns_stock_peer
      SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/gns/gns_stock_peer.cc "${gns_socket_file}"
      LIBRARIES WaterWall::Gns waterwall_cpu_options)
    target_include_directories(gns_stock_peer PRIVATE $<TARGET_PROPERTY:waterwall_gns,INCLUDE_DIRECTORIES>)
    target_compile_definitions(gns_stock_peer PRIVATE $<TARGET_PROPERTY:waterwall_gns,COMPILE_DEFINITIONS>)
    # Upstream's file is built as the library builds its sources, not with the
    # warnings of WaterWall's tests.
    set_source_files_properties("${gns_socket_file}" PROPERTIES COMPILE_OPTIONS "-w;-fno-strict-aliasing")
    target_compile_features(gns_stock_peer PRIVATE cxx_std_20)
    set_target_properties(gns_stock_peer PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
    waterwall_add_native_executable(gns_socket_interop_test SUPPORT
      SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/gns/gns_socket_interop_test.c
      LIBRARIES GnsCommon ww
      DEFINITIONS GNS_STOCK_PEER="$<TARGET_FILE:gns_stock_peer>")
    add_dependencies(gns_socket_interop_test gns_stock_peer)
    waterwall_register_native_test(waterwall.gns_socket_interop_unit gns_socket_interop_test
      "unit;tunnels;gns;session;interop"
      TIMEOUT 120 AGGREGATE waterwall_unit_tests NETWORK_NAMESPACE)
    set_property(TEST waterwall.gns_socket_interop_unit APPEND PROPERTY
      ENVIRONMENT "TSAN_OPTIONS=${WATERWALL_GNS_TSAN_OPTIONS}")
  endif()
endif()
