# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
if(TARGET ConnectionToPackets AND TARGET TcpUdpConnector)
  waterwall_add_native_executable(transport_classifier_matrix_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/transport_classifier_matrix_test.c)
  target_link_libraries(transport_classifier_matrix_test PRIVATE ConnectionToPackets TcpUdpConnector ww)
  add_dependencies(waterwall_unit_tests transport_classifier_matrix_test)
  add_waterwall_unit_test(
    waterwall.transport_classifier_matrix_unit
    transport_classifier_matrix_test
    "unit;tunnels;connectiontopackets;tcpudpconnector;classifier"
  )
endif()

if(LINUX AND TARGET ConnectionToPackets AND TARGET PacketsToConnection)
  foreach(consumer IN ITEMS PacketsToConnection ConnectionToPackets)
    string(TOLOWER "${consumer}" consumer_lower)
    set(fragment_target "${consumer_lower}_fragment_input_test")
    waterwall_add_native_executable(${fragment_target} SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/local_stack_fragment_input_test.c)
  target_link_libraries(${fragment_target} PRIVATE ww_test_support)
    target_compile_definitions(${fragment_target} PRIVATE
      TEST_PACKETS_TO_CONNECTION=$<STREQUAL:${consumer},PacketsToConnection>)
    target_link_libraries(${fragment_target} PRIVATE ${consumer} ww)
    add_dependencies(waterwall_unit_tests ${fragment_target})
    add_waterwall_unit_test(
      waterwall.${consumer_lower}_fragment_input_unit
      ${fragment_target}
      "unit;tunnels;packet;fragment"
    )
  endforeach()
endif()

if(TARGET ConnectionToPackets)
  waterwall_add_native_executable(connectiontopackets_netif_contract_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/packet_bridges/connectiontopackets_netif_contract_test.c)
  target_link_libraries(connectiontopackets_netif_contract_test PRIVATE ConnectionToPackets ww)
  add_dependencies(waterwall_unit_tests connectiontopackets_netif_contract_test)
  add_waterwall_unit_test(
    waterwall.connectiontopackets_netif_contract_unit
    connectiontopackets_netif_contract_test
    "unit;tunnels;connectiontopackets;netif;fragment"
  )
endif()

if(TARGET PacketsToConnection)
  if(TARGET ww_lwip_engine_test)
    get_target_property(ptc_engine_sources PacketsToConnection SOURCES)
    list(TRANSFORM ptc_engine_sources PREPEND "${CMAKE_SOURCE_DIR}/tunnels/PacketsToConnection/")
    add_library(ptc_engine_test STATIC ${ptc_engine_sources})
    target_include_directories(ptc_engine_test PUBLIC ${CMAKE_SOURCE_DIR}/tunnels/PacketsToConnection/include
      PRIVATE ${CMAKE_SOURCE_DIR}/tunnels/PacketsToConnection/include/PacketsToConnection)
    target_link_libraries(ptc_engine_test PUBLIC ww_lwip_engine_test ww)
    target_compile_options(ptc_engine_test PRIVATE -Wno-address-of-packed-member)
    waterwall_add_native_executable(lwip_ptc_engine_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_ptc_engine_test.c ${CMAKE_SOURCE_DIR}/ww/lwip/engine_runtime.c)
  target_link_libraries(lwip_ptc_engine_test PRIVATE ww_test_support)
    target_link_libraries(lwip_ptc_engine_test PRIVATE ptc_engine_test IpOverrider)
    target_link_options(lwip_ptc_engine_test PRIVATE

      "-Wl,--wrap=nodemanagerQuiesceWorker" "-Wl,--wrap=nodemanagerStopWorkerResources"
      "-Wl,--wrap=workerMessagesDestroyDetached")
    add_dependencies(waterwall_unit_tests lwip_ptc_engine_test)
    add_waterwall_unit_test(waterwall.lwip_ptc_engine_unit lwip_ptc_engine_test "unit;net;lwip;thread;packetstoconnection")
    waterwall_add_native_executable(lwip_ptc_trusted_engine_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_ptc_engine_test.c ${CMAKE_SOURCE_DIR}/ww/lwip/engine_runtime.c)
  target_link_libraries(lwip_ptc_trusted_engine_test PRIVATE ww_test_support)
    target_link_libraries(lwip_ptc_trusted_engine_test PRIVATE ptc_engine_test IpOverrider)
    target_link_options(lwip_ptc_trusted_engine_test PRIVATE

      "-Wl,--wrap=nodemanagerQuiesceWorker" "-Wl,--wrap=nodemanagerStopWorkerResources"
      "-Wl,--wrap=workerMessagesDestroyDetached")
    add_dependencies(waterwall_unit_tests lwip_ptc_trusted_engine_test)
    add_waterwall_unit_test(waterwall.lwip_ptc_trusted_engine_unit lwip_ptc_trusted_engine_test "unit;net;lwip;thread;packetstoconnection")
    target_compile_definitions(lwip_ptc_trusted_engine_test PRIVATE PTC_TRUSTED_FIXTURE=1)
  endif()
  waterwall_add_native_executable(packetstoconnection_netif_contract_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/packet_bridges/packetstoconnection_netif_contract_test.c)
  target_link_libraries(packetstoconnection_netif_contract_test PRIVATE PacketsToConnection ww)
  add_dependencies(waterwall_unit_tests packetstoconnection_netif_contract_test)
  add_waterwall_unit_test(
    waterwall.packetstoconnection_netif_contract_unit
    packetstoconnection_netif_contract_test
    "unit;tunnels;packetstoconnection;netif;mtu;fragment"
  )
  waterwall_add_native_executable(packetstoconnection_fake_dns_fragment_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/packet_bridges/packetstoconnection_fake_dns_fragment_test.c)
  target_include_directories(packetstoconnection_fake_dns_fragment_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/PacketsToConnection/include
    ${CMAKE_SOURCE_DIR}/tunnels/PacketsToConnection/include/PacketsToConnection
  )
  target_link_libraries(packetstoconnection_fake_dns_fragment_test PRIVATE PacketsToConnection ww)
  add_dependencies(waterwall_unit_tests packetstoconnection_fake_dns_fragment_test)
  add_waterwall_unit_test(
    waterwall.packetstoconnection_fake_dns_fragment_unit
    packetstoconnection_fake_dns_fragment_test
    "unit;tunnels;packetstoconnection;packet;fragment;dns"
  )

  if(LINUX)
    # The payload source is compiled once more with its unit-only final-admission
    # seam.  The archive's ordinary payload object is not extracted, so normal
    # PacketsToConnection code and layout stay production-identical.
    waterwall_add_native_executable(packetstoconnection_fragment_admission_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/packet_bridges/packetstoconnection_fragment_admission_test.c
      ${CMAKE_SOURCE_DIR}/tunnels/PacketsToConnection/upstream/payload.c)
    target_compile_definitions(packetstoconnection_fragment_admission_test PRIVATE
      PTC_FRAGMENT_ADMISSION_TEST_HOOKS=1
    )
    target_include_directories(packetstoconnection_fragment_admission_test PRIVATE
      ${CMAKE_SOURCE_DIR}/tunnels/PacketsToConnection/include
      ${CMAKE_SOURCE_DIR}/tunnels/PacketsToConnection/include/PacketsToConnection
      ${CMAKE_SOURCE_DIR}/tunnels/PacketsToConnection
      ${CMAKE_SOURCE_DIR}/ww/base
    )
    target_link_options(packetstoconnection_fragment_admission_test PRIVATE
      "-Wl,--wrap=bufferpoolReuseBuffer"
      "-Wl,--wrap=wwLwipEngineInput"
    )
    target_link_libraries(packetstoconnection_fragment_admission_test PRIVATE PacketsToConnection ww)
    add_dependencies(waterwall_unit_tests packetstoconnection_fragment_admission_test)
    add_waterwall_unit_test(
      waterwall.packetstoconnection_fragment_admission_unit
      packetstoconnection_fragment_admission_test
      "unit;tunnels;packetstoconnection;packet;fragment;admission;lifetime"
    )
  endif()
endif()

if(TARGET ww_lwip_engine_test AND TARGET ConnectionToPackets)
  get_target_property(ctp_engine_sources ConnectionToPackets SOURCES)
  list(TRANSFORM ctp_engine_sources PREPEND "${CMAKE_SOURCE_DIR}/tunnels/ConnectionToPackets/")
  add_library(ctp_engine_test STATIC ${ctp_engine_sources})
  target_include_directories(ctp_engine_test PUBLIC ${CMAKE_SOURCE_DIR}/tunnels/ConnectionToPackets/include
    PRIVATE ${CMAKE_SOURCE_DIR}/tunnels/ConnectionToPackets/include/ConnectionToPackets)
  target_link_libraries(ctp_engine_test PUBLIC ww_lwip_engine_test ww DomainResolver)
  target_compile_options(ctp_engine_test PRIVATE -Wno-address-of-packed-member)
  waterwall_add_native_executable(lwip_ctp_roundtrip_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_ctp_roundtrip_test.c
    ${CMAKE_SOURCE_DIR}/ww/lwip/engine_runtime.c)
  target_link_libraries(lwip_ctp_roundtrip_test PRIVATE ww_test_support)
  target_link_libraries(lwip_ctp_roundtrip_test PRIVATE ctp_engine_test ptc_engine_test)
  target_link_options(lwip_ctp_roundtrip_test PRIVATE

    "-Wl,--wrap=nodemanagerQuiesceWorker" "-Wl,--wrap=nodemanagerStopWorkerResources"
    "-Wl,--wrap=workerMessagesDestroyDetached")
  add_dependencies(waterwall_unit_tests lwip_ctp_roundtrip_test)
  add_waterwall_unit_test(waterwall.lwip_ctp_roundtrip_unit lwip_ctp_roundtrip_test "unit;net;lwip;thread;connectiontopackets")

endif()

if(LINUX AND TARGET ConnectionToPackets)
  waterwall_add_native_executable(connectiontopackets_schedule_rejection_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/packet_bridges/connectiontopackets_schedule_rejection_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}

    ${CMAKE_SOURCE_DIR}/ww/lwip/engine_runtime.c)

  target_link_options(connectiontopackets_schedule_rejection_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=lineScheduleTask"
    "-Wl,--wrap=lineScheduleTaskWithBuf"


  )
  target_link_libraries(connectiontopackets_schedule_rejection_test PRIVATE ctp_engine_test)
  add_dependencies(waterwall_unit_tests connectiontopackets_schedule_rejection_test)
  add_waterwall_unit_test(
    waterwall.connectiontopackets_schedule_rejection_unit
    connectiontopackets_schedule_rejection_test
    "unit;tunnels;connectiontopackets;lwip;scheduling;rejection;buffers;ownership"
  )
endif()

if(LINUX AND TARGET PacketsToConnection)
  waterwall_add_native_executable(packetstoconnection_schedule_rejection_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/packet_bridges/packetstoconnection_schedule_rejection_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}

    ${CMAKE_SOURCE_DIR}/ww/lwip/engine_runtime.c)

  target_link_options(packetstoconnection_schedule_rejection_test PRIVATE
    "-Wl,--wrap=tcp_write"
    "-Wl,--wrap=sendWorkerMessageForceQueueWithCleanup"
    "-Wl,--wrap=memoryAllocate"
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=lineScheduleTask"
    "-Wl,--wrap=lineScheduleTaskWithBuf"


  )
  # Scaled TCP admission needs the production payload pools; the miniature
  # engine fixture cannot hold even one 64 KiB tcp_write(COPY).
  target_link_libraries(packetstoconnection_schedule_rejection_test PRIVATE PacketsToConnection ww)
  add_dependencies(waterwall_unit_tests packetstoconnection_schedule_rejection_test)
  add_waterwall_unit_test(
    waterwall.packetstoconnection_schedule_rejection_unit
    packetstoconnection_schedule_rejection_test
    "unit;tunnels;packetstoconnection;lwip;scheduling;rejection;credit;buffers;ownership"
  )
endif()


if(LINUX AND TARGET PacketsToConnection)
  waterwall_add_native_executable(packetstoconnection_receive_batch_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/packet_bridges/packetstoconnection_receive_batch_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/PacketsToConnection/upstream/payload.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
    ${CMAKE_SOURCE_DIR}/ww/lwip/engine_runtime.c)
  target_compile_definitions(packetstoconnection_receive_batch_test PRIVATE PTC_FRAGMENT_ADMISSION_TEST_HOOKS=1)
  target_include_directories(packetstoconnection_receive_batch_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/PacketsToConnection/include/PacketsToConnection
  )
  target_link_options(packetstoconnection_receive_batch_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=lineScheduleTask"
    "-Wl,--wrap=lineScheduleTaskWithBuf"
    "-Wl,--wrap=wwLwipEngineInput"
  )
  target_link_libraries(packetstoconnection_receive_batch_test PRIVATE PacketsToConnection ww)
  add_dependencies(waterwall_unit_tests packetstoconnection_receive_batch_test)
  add_waterwall_unit_test(
    waterwall.packetstoconnection_receive_batch_unit
    packetstoconnection_receive_batch_test
    "unit;tunnels;packetstoconnection;lwip;scheduling;credit;buffers;ownership"
  )
endif()

