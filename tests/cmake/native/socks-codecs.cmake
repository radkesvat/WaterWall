# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
foreach(side IN ITEMS client server)
  if(side STREQUAL "client")
    set(halfduplex_node HalfDuplexClient)
    set(halfduplex_fixture ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/halfduplex/halfduplexclient_framing_random_test.c)
  else()
    set(halfduplex_node HalfDuplexServer)
    set(halfduplex_fixture ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/halfduplex/halfduplexserver_reentrant_init_test.c)
  endif()
  if(TARGET ${halfduplex_node} AND CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
    set(halfduplex_test halfduplex${side}_no_splice_test)
    waterwall_add_native_executable(${halfduplex_test} SOURCES ${halfduplex_fixture} ${WATERWALL_LINE_FAILURE_WW_SOURCES})
    waterwall_line_failure_test_use_tunnel(${halfduplex_test} ${halfduplex_node})
    target_compile_definitions(${halfduplex_test} PRIVATE WW_HAVE_SPLICE=0 WW_HALFDUPLEXSERVER_RENDEZVOUS_TEST_SEAM=1)
    target_link_options(${halfduplex_test} PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
    if(side STREQUAL "server")
      target_link_options(${halfduplex_test} PRIVATE "-Wl,--wrap=lineScheduleTask" "-Wl,--wrap=sbufAppendMerge" "-Wl,--wrap=bufferqueueTryPushBack")
    endif()
    target_link_libraries(${halfduplex_test} PRIVATE ww)
    add_dependencies(waterwall_unit_tests ${halfduplex_test})
    add_waterwall_unit_test(waterwall.halfduplex${side}_no_splice_unit ${halfduplex_test} "unit;tunnels;halfduplex;no-splice")
  endif()
endforeach()

if(LINUX AND TARGET Socks5Server)
  waterwall_add_native_executable(socks5server_control_input_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/socks/socks5server_control_input_test.c ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  target_include_directories(socks5server_control_input_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TcpUdpListener/include
    ${CMAKE_SOURCE_DIR}/tunnels/UdpListener/include
    ${CMAKE_SOURCE_DIR}/tunnels/AuthenticationClient/include)
  target_link_options(socks5server_control_input_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=authenticationclientGetState" "-Wl,--wrap=authenticationclientGetUserByPasswordWithResult")
  target_link_libraries(socks5server_control_input_test PRIVATE Socks5Server ww)
  add_dependencies(waterwall_unit_tests socks5server_control_input_test)
  add_waterwall_unit_test(waterwall.socks5server_control_input_unit socks5server_control_input_test "unit;tunnels;socks5server;reentrant;input")
endif()

if(TARGET Socks5Server)
  waterwall_add_native_executable(socks5server_address_codec_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/socks/socks5server_address_codec_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/Socks5Server/common/address_codec.c)
  target_include_directories(socks5server_address_codec_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/Socks5Server/include
    ${CMAKE_SOURCE_DIR}/tunnels/Socks5Server/include/Socks5Server)
  add_dependencies(waterwall_unit_tests socks5server_address_codec_test)
  add_waterwall_unit_test(waterwall.socks5server_address_codec_unit socks5server_address_codec_test "unit;socks5server;codec")
endif()

if(LINUX AND TARGET Socks5Server)
  waterwall_add_native_executable(socks5server_resources_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/socks/socks5server_resources_test.c ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(socks5server_resources_test Socks5Server)
  target_link_options(socks5server_resources_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=memoryAllocate" "-Wl,--wrap=memoryCalloc" "-Wl,--wrap=memoryReAllocate")
  target_link_libraries(socks5server_resources_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests socks5server_resources_test)
  add_waterwall_unit_test(waterwall.socks5server_resources_unit socks5server_resources_test "unit;socks5server;allocation;ownership")
endif()

if(LINUX AND TARGET Socks5Server)
  waterwall_add_native_executable(socks5server_udp_identity_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/socks/socks5server_udp_identity_test.c ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(socks5server_udp_identity_test Socks5Server)
  target_compile_definitions(socks5server_udp_identity_test PRIVATE SOCKS5SERVER_TEST_CONSTANT_HASH=1)
  target_link_options(socks5server_udp_identity_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(socks5server_udp_identity_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests socks5server_udp_identity_test)
  add_waterwall_unit_test(waterwall.socks5server_udp_identity_unit socks5server_udp_identity_test "unit;socks5server;udp;collision;ownership;reentrant")
endif()

if(LINUX AND TARGET Socks5Client)
  waterwall_add_native_executable(socks5client_reply_input_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/socks/socks5client_reply_input_test.c ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(socks5client_reply_input_test Socks5Client)
  target_link_options(socks5client_reply_input_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(socks5client_reply_input_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests socks5client_reply_input_test)
  add_waterwall_unit_test(waterwall.socks5client_reply_input_unit socks5client_reply_input_test "unit;socks5client;reentrant;input;ownership")
endif()

if(LINUX AND TARGET Socks5Client)
  waterwall_add_native_executable(socks5client_resources_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/socks/socks5client_resources_test.c ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(socks5client_resources_test Socks5Client)
  target_link_options(socks5client_resources_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=memoryAllocate" "-Wl,--wrap=memoryReAllocate")
  target_link_libraries(socks5client_resources_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests socks5client_resources_test)
  add_waterwall_unit_test(waterwall.socks5client_resources_unit socks5client_resources_test "unit;socks5client;allocation;ownership")
endif()

foreach(side IN ITEMS Client Server)
  if(TARGET Trojan${side})
    string(TOLOWER "Trojan${side}" trojan_codec_prefix)
    set(trojan_codec_test ${trojan_codec_prefix}_address_codec_test)
    waterwall_add_native_executable(${trojan_codec_test} SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/trojan/trojan_address_codec_test.c
      ${CMAKE_SOURCE_DIR}/tunnels/Trojan${side}/common/address_codec.c)
    target_include_directories(${trojan_codec_test} PRIVATE
      ${CMAKE_SOURCE_DIR}/tunnels/Trojan${side}/include
      ${CMAKE_SOURCE_DIR}/tunnels/Trojan${side}/include/Trojan${side})
    if(side STREQUAL "Server")
      target_compile_definitions(${trojan_codec_test} PRIVATE TROJAN_ADDRESS_SERVER=1)
    endif()
    add_dependencies(waterwall_unit_tests ${trojan_codec_test})
    add_waterwall_unit_test(waterwall.${trojan_codec_prefix}_address_codec_unit ${trojan_codec_test} "unit;trojan;codec")
  endif()
endforeach()

