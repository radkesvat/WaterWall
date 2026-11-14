# ENet units are pure C: no socket, worker runtime or wall clock. The driver
# tests run over the in-memory link in tests/unittests/tunnels/enet/enet_sim.h.
if(TARGET EnetCommon)
  waterwall_add_native_executable(enet_platform_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/enet/enet_platform_test.c
    INCLUDES ${CMAKE_SOURCE_DIR}/tunnels/Internals/EnetCommon/src
    LIBRARIES EnetCommon ww)
  set_target_properties(enet_platform_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
  add_waterwall_unit_test(waterwall.enet_platform_unit enet_platform_test "unit;tunnels;enet;platform")
  waterwall_add_native_executable(enet_driver_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/enet/enet_driver_test.c
    LIBRARIES EnetCommon ww)
  set_target_properties(enet_driver_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
  add_waterwall_unit_test(waterwall.enet_driver_unit enet_driver_test "unit;tunnels;enet;driver;close;pressure")
  waterwall_add_native_executable(enet_native_peer_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/enet/enet_native_peer_test.c
    INCLUDES ${CMAKE_SOURCE_DIR}/tunnels/Internals/EnetCommon/src
    LIBRARIES EnetCommon ww)
  set_target_properties(enet_native_peer_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
  add_waterwall_unit_test(waterwall.enet_native_peer_unit enet_native_peer_test "unit;tunnels;enet;driver;interop")
  waterwall_add_native_executable(enet_throughput_sim_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/enet/enet_throughput_sim_test.c
    LIBRARIES EnetCommon ww)
  set_target_properties(enet_throughput_sim_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
  add_waterwall_unit_test(waterwall.enet_throughput_sim_unit enet_throughput_sim_test
    "unit;tunnels;enet;driver;throughput")
  # The archive check needs plain object code; the unit tree builds without IPO.
  if(CMAKE_NM AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_dependencies(waterwall_unit_tests EnetCommon)
    add_test(NAME waterwall.enet_no_os_socket_symbols
      COMMAND "${CMAKE_COMMAND}"
        "-DNM=${CMAKE_NM}"
        "-DENET_ARCHIVE=$<TARGET_FILE:EnetCommon>"
        -P "${CMAKE_SOURCE_DIR}/tests/enet_no_os_socket_symbols.cmake")
    set_tests_properties(waterwall.enet_no_os_socket_symbols PROPERTIES
      TIMEOUT 30 LABELS "unit;policy;build;linking;enet")
  endif()
endif()

# The node layer uses the WaterWall API: settings, the worker session and the tunnel logic of both roles.
if(TARGET EnetTunnelCommon)
  waterwall_add_native_executable(enet_settings_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/enet/enet_settings_test.c
    LIBRARIES EnetTunnelCommon ww)
  add_waterwall_unit_test(waterwall.enet_settings_unit enet_settings_test "unit;tunnels;enet;settings")
  waterwall_add_native_executable(enet_session_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/enet/enet_session_test.c
    LIBRARIES EnetTunnelCommon ww)
  add_waterwall_unit_test(waterwall.enet_session_unit enet_session_test
    "unit;tunnels;enet;session;close;pressure" 120)
  # The pair test replaces the clock at link time, which needs GNU ld's --wrap option.
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TARGET EnetClient AND TARGET EnetServer)
    waterwall_add_native_executable(enet_pair_test SUPPORT
      SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/enet/enet_pair_test.c
      LIBRARIES EnetClient EnetServer EnetTunnelCommon ww)
    target_link_options(enet_pair_test PRIVATE "-Wl,--wrap=getHRTimeUs")
    add_waterwall_unit_test(waterwall.enet_pair_unit enet_pair_test
      "unit;tunnels;enet;line;close;pressure;lifecycle" 120)
  endif()
  # The socket interop test runs a plain ENet application in a second process: the vendored core with upstream's
  # own socket layer, which defines the same functions as EnetCommon's platform layer.
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    waterwall_add_native_executable(enet_stock_peer
      SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/enet/enet_stock_peer.c
              ${CMAKE_SOURCE_DIR}/ww/vendor/enet/unix.c
              $<TARGET_OBJECTS:enet_protocol>
      INCLUDES ${CMAKE_SOURCE_DIR}/ww/vendor/enet/include
      LIBRARIES waterwall_runtime_options
      DEFINITIONS HAS_FCNTL=1 HAS_POLL=1 HAS_INET_PTON=1 HAS_INET_NTOP=1 HAS_MSGHDR_FLAGS=1 HAS_SOCKLEN_T=1
                  HAS_GETADDRINFO=1 HAS_GETNAMEINFO=1)
    set_target_properties(enet_stock_peer PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
    waterwall_add_native_executable(enet_socket_interop_test SUPPORT
      SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/enet/enet_socket_interop_test.c
      LIBRARIES EnetTunnelCommon ww
      DEFINITIONS ENET_STOCK_PEER="$<TARGET_FILE:enet_stock_peer>")
    add_dependencies(enet_socket_interop_test enet_stock_peer)
    add_waterwall_unit_test(waterwall.enet_socket_interop_unit enet_socket_interop_test
      "unit;tunnels;enet;session;interop" 60)
  endif()
endif()
