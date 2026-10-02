# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
if(TARGET IpManipulator)
  waterwall_add_native_executable(ipmanipulator_tcpbit_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ipmanipulator/ipmanipulator_tcpbit_test.c)
  target_include_directories(ipmanipulator_tcpbit_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_tcpbit_test PRIVATE IpManipulator ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_tcpbit_test)

  add_waterwall_unit_test(waterwall.ipmanipulator_tcpbit_unit ipmanipulator_tcpbit_test "unit;tunnels;ipmanipulator")

  waterwall_add_native_executable(ipmanipulator_syn_predicate_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ipmanipulator/ipmanipulator_syn_predicate_test.c)
  target_include_directories(ipmanipulator_syn_predicate_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_syn_predicate_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_syn_predicate_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_syn_predicate_unit
    ipmanipulator_syn_predicate_test
    "unit;tunnels;ipmanipulator;tcp;configuration"
  )

  waterwall_add_native_executable(ipmanipulator_flow_table_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ipmanipulator/ipmanipulator_flow_table_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/flow_table.c)
  target_include_directories(ipmanipulator_flow_table_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_flow_table_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_flow_table_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_flow_table_unit
    ipmanipulator_flow_table_test
    "unit;tunnels;ipmanipulator;flowtable;bounded;hashing"
  )

  waterwall_add_native_executable(ipmanipulator_delay_barrier_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ipmanipulator/ipmanipulator_delay_barrier_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/flow_table.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/helpers.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/portghost/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/protoswap/trick.c)
  target_include_directories(ipmanipulator_delay_barrier_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_compile_definitions(ipmanipulator_delay_barrier_test PRIVATE IPMANIPULATOR_DELAY_BARRIER_TEST_HOOKS=1)
  target_link_libraries(ipmanipulator_delay_barrier_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_delay_barrier_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_delay_barrier_unit
    ipmanipulator_delay_barrier_test
    "unit;tunnels;ipmanipulator;firstsni;smugglesni;overlapsni;delay;fifo;lifecycle;worker;ownership"
  )

  waterwall_add_native_executable(ipmanipulator_config_validation_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ipmanipulator/ipmanipulator_config_validation_test.c)
  target_include_directories(ipmanipulator_config_validation_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_config_validation_test PRIVATE IpManipulator ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_config_validation_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_config_validation_unit
    ipmanipulator_config_validation_test
    "unit;tunnels;ipmanipulator;configuration;tcpbit;sni"
  )

  waterwall_add_native_executable(ipmanipulator_protoswap_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ipmanipulator/ipmanipulator_protoswap_test.c)
  target_include_directories(ipmanipulator_protoswap_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_protoswap_test PRIVATE IpManipulator ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_protoswap_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_protoswap_unit
    ipmanipulator_protoswap_test
    "unit;tunnels;ipmanipulator;protoswap;checksum"
  )

  waterwall_add_native_executable(ipmanipulator_egress_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ipmanipulator/ipmanipulator_egress_test.c)
  target_include_directories(ipmanipulator_egress_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_egress_test PRIVATE IpManipulator ww)
  if(TARGET IpOverrider)
    target_link_libraries(ipmanipulator_egress_test PRIVATE IpOverrider)
    target_compile_definitions(ipmanipulator_egress_test PRIVATE TEST_PROTOSWAP_IPOVERRIDER=1)
  endif()
  add_dependencies(waterwall_unit_tests ipmanipulator_egress_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_egress_unit
    ipmanipulator_egress_test
    "unit;tunnels;ipmanipulator;protoswap;portghost;sniblender;checksum;lifecycle"
  )

  waterwall_add_native_executable(ipmanipulator_worker_mismatch_log_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ipmanipulator/ipmanipulator_worker_mismatch_log_test.c)
  target_include_directories(ipmanipulator_worker_mismatch_log_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_worker_mismatch_log_test PRIVATE IpManipulator ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_worker_mismatch_log_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_worker_mismatch_log_unit
    ipmanipulator_worker_mismatch_log_test
    "unit;tunnels;ipmanipulator;logging;workers"
  )

  waterwall_add_native_executable(ipmanipulator_firstsni_offsets_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ipmanipulator/ipmanipulator_firstsni_offsets_test.c)
  target_include_directories(ipmanipulator_firstsni_offsets_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_firstsni_offsets_test PRIVATE IpManipulator ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_firstsni_offsets_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_firstsni_offsets_unit
    ipmanipulator_firstsni_offsets_test
    "unit;tunnels;ipmanipulator;firstsni;tls"
  )

  waterwall_add_native_executable(ipmanipulator_echsni_delay_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ipmanipulator/ipmanipulator_echsni_delay_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/flow_table.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/helpers.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/echsnitrick/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/portghost/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/protoswap/trick.c)
  target_include_directories(ipmanipulator_echsni_delay_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_compile_definitions(ipmanipulator_echsni_delay_test PRIVATE IPMANIPULATOR_ECHSNI_TEST_HOOKS=1)
  target_link_libraries(ipmanipulator_echsni_delay_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_echsni_delay_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_echsni_delay_unit
    ipmanipulator_echsni_delay_test
    "unit;tunnels;ipmanipulator;echsni;delay;lifecycle;worker;ownership"
  )

  waterwall_add_native_executable(ipmanipulator_smugglesni_capture_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ipmanipulator/ipmanipulator_smugglesni_capture_test.c)
  target_include_directories(ipmanipulator_smugglesni_capture_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_smugglesni_capture_test PRIVATE IpManipulator ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_smugglesni_capture_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_smugglesni_capture_unit
    ipmanipulator_smugglesni_capture_test
    "unit;tunnels;ipmanipulator;smugglesni;tls;worker;ownership"
  )

  waterwall_add_native_executable(ipmanipulator_smugglefin_pause_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ipmanipulator/ipmanipulator_smugglefin_pause_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/flow_table.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/portghost/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/protoswap/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/smugglefin/trick.c)
  target_include_directories(ipmanipulator_smugglefin_pause_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_compile_definitions(ipmanipulator_smugglefin_pause_test PRIVATE IPMANIPULATOR_SMUGGLEFIN_TEST_HOOKS=1)
  target_link_libraries(ipmanipulator_smugglefin_pause_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_smugglefin_pause_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_smugglefin_pause_unit
    ipmanipulator_smugglefin_pause_test
    "unit;tunnels;ipmanipulator;smugglefin;timeout;affinity"
  )

  waterwall_add_native_executable(ipmanipulator_overlap_hold_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ipmanipulator/ipmanipulator_overlap_hold_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/flow_table.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/helpers.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/overlapsni/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/portghost/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/protoswap/trick.c)
  target_include_directories(ipmanipulator_overlap_hold_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
  )
  target_compile_definitions(ipmanipulator_overlap_hold_test PRIVATE IPMANIPULATOR_OVERLAP_TEST_HOOKS=1)
  target_link_libraries(ipmanipulator_overlap_hold_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_overlap_hold_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_overlap_hold_unit
    ipmanipulator_overlap_hold_test
    "unit;tunnels;ipmanipulator;overlapsni;timeout;lifecycle;worker;ownership"
  )

  waterwall_add_native_executable(ipmanipulator_synfin_hold_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ipmanipulator/ipmanipulator_synfin_hold_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/flow_table.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/helpers.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/synfinsni/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/portghost/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/protoswap/trick.c)
  target_include_directories(ipmanipulator_synfin_hold_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
  )
  target_compile_definitions(ipmanipulator_synfin_hold_test PRIVATE IPMANIPULATOR_SYNFIN_TEST_HOOKS=1)
  target_link_libraries(ipmanipulator_synfin_hold_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_synfin_hold_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_synfin_hold_unit
    ipmanipulator_synfin_hold_test
    "unit;tunnels;ipmanipulator;synfinsni;timeout;lifecycle;worker;ownership"
  )

  if(TARGET TlsClient)
    waterwall_add_native_executable(ipmanipulator_internal_tls_child_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ipmanipulator/ipmanipulator_internal_tls_child_test.c)
    target_include_directories(ipmanipulator_internal_tls_child_test PRIVATE
      ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
      ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
      ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
    )
    target_link_libraries(ipmanipulator_internal_tls_child_test PRIVATE
      IpManipulator TlsClient ww ssl crypto
    )
    add_dependencies(waterwall_unit_tests ipmanipulator_internal_tls_child_test)

    add_waterwall_unit_test(
      waterwall.ipmanipulator_internal_tls_child_unit
      ipmanipulator_internal_tls_child_test
      "unit;tunnels;ipmanipulator;tlsclient;configuration;ownership"
    )
  endif()
endif()

