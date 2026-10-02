# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
waterwall_add_native_executable(bound_udp_socket_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/udp/bound_udp_socket_test.c
  ${WATERWALL_LINE_FAILURE_WW_SOURCES})
target_link_options(bound_udp_socket_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
if(LINUX)
  target_link_options(bound_udp_socket_test PRIVATE "-Wl,--wrap=setsockopt")
endif()
target_link_libraries(bound_udp_socket_test PRIVATE ww)
add_dependencies(waterwall_unit_tests bound_udp_socket_test)
add_waterwall_unit_test(
  waterwall.bound_udp_socket_unit
  bound_udp_socket_test
  "unit;net;udp;socket;bound;ephemeral"
)

if(TARGET UdpListener)
  waterwall_add_native_executable(udplistener_acl_copy_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/udp/udplistener_acl_copy_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/UdpListener/instance/create.c
    ${CMAKE_SOURCE_DIR}/tunnels/UdpListener/instance/destroy.c)
  set_target_properties(udplistener_acl_copy_test PROPERTIES INTERPROCEDURAL_OPTIMIZATION OFF)
  target_compile_definitions(udplistener_acl_copy_test PRIVATE UDPLISTENER_CREATE_TEST_HOOKS=1)
  target_include_directories(
    udplistener_acl_copy_test
    PRIVATE
      ${CMAKE_SOURCE_DIR}/tunnels/UdpListener/include
      ${CMAKE_SOURCE_DIR}/tunnels/UdpListener/include/UdpListener
  )
  if(LINUX)
    target_link_options(udplistener_acl_copy_test PRIVATE
      "-Wl,--wrap=socketacceptorRegister"
      "-Wl,--wrap=socketfilteroptionDeInit"
      "-Wl,--wrap=tunnelDestroy"
    )
  endif()
  target_link_libraries(udplistener_acl_copy_test PRIVATE UdpListener ww)
  add_dependencies(waterwall_unit_tests udplistener_acl_copy_test)
  add_waterwall_unit_test(
    waterwall.udplistener_acl_copy_unit
    udplistener_acl_copy_test
    "unit;tunnels;udplistener;acl;allocation;startup"
  )

  if(TARGET TcpUdpListener)
    waterwall_add_native_executable(tcpudplistener_dynamic_provider_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tcpudp/tcpudplistener_dynamic_provider_test.c)
    target_include_directories(
      tcpudplistener_dynamic_provider_test
      PRIVATE
        ${CMAKE_SOURCE_DIR}/tunnels/TcpUdpListener/include
        ${CMAKE_SOURCE_DIR}/tunnels/TcpUdpListener/include/TcpUdpListener
        ${CMAKE_SOURCE_DIR}/tunnels/UdpListener/include
        ${CMAKE_SOURCE_DIR}/tunnels/UdpListener/include/UdpListener
    )
    target_link_libraries(tcpudplistener_dynamic_provider_test PRIVATE TcpUdpListener UdpListener ww)
    add_dependencies(waterwall_unit_tests tcpudplistener_dynamic_provider_test)
    add_waterwall_unit_test(
      waterwall.tcpudplistener_dynamic_provider_unit
      tcpudplistener_dynamic_provider_test
      "unit;tunnels;tcpudplistener;udplistener;udp;dynamic;provider;delegation"
    )
  endif()

  waterwall_add_native_executable(udplistener_dynamic_endpoint_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/udp/udplistener_dynamic_endpoint_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(udplistener_dynamic_endpoint_test UdpListener)
  target_compile_definitions(udplistener_dynamic_endpoint_test PRIVATE UDPLISTENER_DYNAMIC_ENDPOINT_TEST_HOOKS=1)
  target_link_options(udplistener_dynamic_endpoint_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  if(LINUX)
    target_link_options(udplistener_dynamic_endpoint_test PRIVATE "-Wl,--wrap=wioRead" "-Wl,--wrap=udpSendBuffer")
  endif()
  target_link_libraries(udplistener_dynamic_endpoint_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests udplistener_dynamic_endpoint_test)

  add_waterwall_unit_test(
    waterwall.udplistener_dynamic_endpoint_unit
    udplistener_dynamic_endpoint_test
    "unit;tunnels;udplistener;udp;dynamic;endpoint;lifecycle"
  )
endif()

if(TARGET UdpConnector)
  waterwall_add_native_executable(udpconnector_socket_pool_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/udp/udpconnector_socket_pool_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(udpconnector_socket_pool_test UdpConnector)
  target_compile_definitions(udpconnector_socket_pool_test PRIVATE UDPCONNECTOR_POOL_TEST_HOOKS=1)
  target_link_options(udpconnector_socket_pool_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  if(LINUX)
    target_link_options(udpconnector_socket_pool_test PRIVATE "-Wl,--wrap=wioRead" "-Wl,--wrap=udpSendBuffer")
    target_link_options(udpconnector_socket_pool_test PRIVATE "-Wl,--wrap=wioWriteDatagram")
  endif()
  target_link_libraries(udpconnector_socket_pool_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests udpconnector_socket_pool_test)

  add_waterwall_unit_test(
    waterwall.udpconnector_socket_pool_unit
    udpconnector_socket_pool_test
    "unit;tunnels;udpconnector;udp;socket;pool;lifecycle;tsan"
  )
endif()

if(TARGET UdpConnector AND TARGET PacketsToStream AND TARGET PacketSender)
  waterwall_add_native_executable(udpconnector_layer_metadata_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/udp/udpconnector_layer_metadata_test.c)
  target_link_libraries(udpconnector_layer_metadata_test PRIVATE
    UdpConnector
    PacketsToStream
    PacketSender
    ww
  )
  add_dependencies(waterwall_unit_tests udpconnector_layer_metadata_test)

  add_waterwall_unit_test(
    waterwall.udpconnector_layer_metadata_unit
    udpconnector_layer_metadata_test
    "unit;tunnels;udpconnector;packetstostream;layer;metadata"
  )
endif()

if(TARGET PacketReceiver)
  waterwall_add_native_executable(packetreceiver_protocol_settings_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/packet_io/packetreceiver_protocol_settings_test.c)
  target_link_libraries(packetreceiver_protocol_settings_test PRIVATE PacketReceiver ww)
  add_dependencies(waterwall_unit_tests packetreceiver_protocol_settings_test)
  add_waterwall_unit_test(
    waterwall.packetreceiver_protocol_settings_unit
    packetreceiver_protocol_settings_test
    "unit;tunnels;packetreceiver;packet-analysis;configuration"
  )
endif()

waterwall_add_native_executable(local_idle_table_indexed_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/local_idle_table_indexed_test.c)
  target_link_libraries(local_idle_table_indexed_test PRIVATE ww_test_support)
target_link_libraries(local_idle_table_indexed_test PRIVATE ww)
add_dependencies(waterwall_unit_tests local_idle_table_indexed_test)
add_waterwall_unit_test(
  waterwall.local_idle_table_indexed_unit
  local_idle_table_indexed_test
  "unit;base;local-idle;heap;lifetime;tsan"
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  waterwall_add_native_executable(system_memory_linux_provider_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/system_memory_linux_provider_test.c)
  target_link_libraries(system_memory_linux_provider_test PRIVATE ww_test_support)
  target_link_libraries(system_memory_linux_provider_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests system_memory_linux_provider_test)
  add_waterwall_unit_test(
    waterwall.system_memory_linux_provider_unit
    system_memory_linux_provider_test
    "unit;base;system-memory;linux;cgroup;provider"
  )
endif()

