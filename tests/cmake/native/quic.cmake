# Compile the production C carrier directly: no socket, WW runtime or C++ engine
# is needed to exercise its fragmentation/admission/ownership boundary.
if(TARGET QuicCommon)
  waterwall_add_native_executable(quic_carrier_test SUPPORT
    SOURCES
      ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/quic/quic_carrier_test.c
      ${CMAKE_SOURCE_DIR}/tunnels/Internals/QuicCommon/carrier.c
    INCLUDES ${CMAKE_SOURCE_DIR}/tunnels/Internals/QuicCommon)
  set_target_properties(quic_carrier_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
  add_waterwall_unit_test(waterwall.quic_carrier_unit quic_carrier_test "unit;tunnels;quic;framing;ownership")
endif()

if(TARGET QuicClient OR TARGET QuicServer)
  set(quic_node_test_libraries QuicCommon ww)
  if(TARGET QuicClient)
    list(APPEND quic_node_test_libraries QuicClient)
  endif()
  if(TARGET QuicServer)
    list(APPEND quic_node_test_libraries QuicServer)
  endif()
  waterwall_add_native_executable(quic_node_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/quic/quic_node_test.c
    INCLUDES ${CMAKE_SOURCE_DIR}/tunnels/Internals/QuicCommon
    LIBRARIES ${quic_node_test_libraries}
    DEFINITIONS
      QUIC_TEST_HAS_CLIENT=$<BOOL:$<TARGET_EXISTS:QuicClient>>
      QUIC_TEST_HAS_SERVER=$<BOOL:$<TARGET_EXISTS:QuicServer>>
      QUIC_TEST_CERT="${CMAKE_SOURCE_DIR}/tests/speedtests/_shared/server.crt"
      QUIC_TEST_KEY="${CMAKE_SOURCE_DIR}/tests/speedtests/_shared/server.key")
  target_link_options(quic_node_test PRIVATE
    "-Wl,--wrap=abortProgramNow" "-Wl,--wrap=requestProgramShutdown"
    "-Wl,--wrap=bufferpoolGetLargeBuffer" "-Wl,--wrap=bufferpoolGetSmallBuffer"
    "-Wl,--wrap=bufferpoolGetMediumBuffer" "-Wl,--wrap=bufferpoolTryGetBestFit"
    "-Wl,--wrap=bufferpoolGetBestFit" "-Wl,--wrap=bufferpoolGetSpliceBuffer"
    "-Wl,--wrap=bufferpoolReuseBuffer" "-Wl,--wrap=sbufDestroy")
  set_target_properties(quic_node_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
  add_waterwall_unit_test(waterwall.quic_node_unit quic_node_test "unit;tunnels;quic;lifecycle;reentry;ownership")
endif()

if(TARGET QuicCommon)
  waterwall_add_native_executable(quic_engine_test SUPPORT
    SOURCES
      ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/quic/quic_engine_test.cc
      ${CMAKE_SOURCE_DIR}/ww/utils/cacert.c
    INCLUDES ${CMAKE_SOURCE_DIR}/tunnels/Internals/QuicCommon
    LIBRARIES WaterWall::Quiche WaterWall::BoringSSL waterwall_cpu_options
    DEFINITIONS
      QUIC_TEST_CERT="${CMAKE_SOURCE_DIR}/tests/speedtests/_shared/server.crt"
      QUIC_TEST_KEY="${CMAKE_SOURCE_DIR}/tests/speedtests/_shared/server.key")
  target_compile_features(quic_engine_test PRIVATE cxx_std_20)
  set_target_properties(quic_engine_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
  add_waterwall_unit_test(waterwall.quic_engine_unit quic_engine_test "unit;tunnels;quic;crypto;loss;ownership")
endif()
