# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
if(LINUX AND TARGET RawSocket)
  waterwall_add_native_executable(rawsocket_ipv4_boundary_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/rawsocket/rawsocket_ipv4_boundary_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(rawsocket_ipv4_boundary_test RawSocket)
  target_link_options(rawsocket_ipv4_boundary_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=rawdeviceWrite"
  )
  target_link_libraries(rawsocket_ipv4_boundary_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests rawsocket_ipv4_boundary_test)
  add_waterwall_unit_test(
    waterwall.rawsocket_ipv4_boundary_unit
    rawsocket_ipv4_boundary_test
    "unit;net;packet;rawsocket;boundary"
  )
endif()

if(TARGET HttpClient)
  waterwall_add_native_executable(httpclient_wire_profile_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/http/httpclient_wire_profile_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(httpclient_wire_profile_test HttpClient)
  target_link_options(httpclient_wire_profile_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(httpclient_wire_profile_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests httpclient_wire_profile_test)
  add_waterwall_unit_test(
    waterwall.httpclient_wire_profile_unit
    httpclient_wire_profile_test
    "unit;tunnels;httpclient;framing;http2;reentrant"
    30
  )

  waterwall_add_native_executable(httpclient_chunked_terminator_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/http/httpclient_chunked_terminator_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(httpclient_chunked_terminator_test HttpClient)
  target_link_options(httpclient_chunked_terminator_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(httpclient_chunked_terminator_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests httpclient_chunked_terminator_test)

  add_waterwall_unit_test(
    waterwall.httpclient_chunked_terminator_unit
    httpclient_chunked_terminator_test
    "unit;tunnels;httpclient;chunked;framing"
    30
  )

  waterwall_add_native_executable(httpclient_reentrant_finish_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/http/httpclient_reentrant_finish_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(httpclient_reentrant_finish_test HttpClient)
  target_link_options(httpclient_reentrant_finish_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=bufferpoolGetLargeBufferSize"
  )
  target_link_libraries(httpclient_reentrant_finish_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests httpclient_reentrant_finish_test)

  add_waterwall_unit_test(
    waterwall.httpclient_reentrant_finish_unit
    httpclient_reentrant_finish_test
    "unit;tunnels;httpclient;reentrant;finish;line"
  )

  waterwall_add_native_executable(httpclient_split_id_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/http/httpclient_split_id_test.c)
  target_link_libraries(httpclient_split_id_test PRIVATE HttpClient ww)
  add_dependencies(waterwall_unit_tests httpclient_split_id_test)

  add_waterwall_unit_test(
    waterwall.httpclient_split_id_unit
    httpclient_split_id_test
    "unit;tunnels;httpclient;split;id;random"
    30
  )
endif()

if(TARGET HttpServer)
  waterwall_add_native_executable(httpserver_chunked_terminator_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/http/httpserver_chunked_terminator_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(httpserver_chunked_terminator_test HttpServer)
  target_link_options(httpserver_chunked_terminator_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(httpserver_chunked_terminator_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests httpserver_chunked_terminator_test)

  add_waterwall_unit_test(
    waterwall.httpserver_chunked_terminator_unit
    httpserver_chunked_terminator_test
    "unit;tunnels;httpserver;chunked;framing"
    30
  )

  waterwall_add_native_executable(httpserver_reentrant_finish_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/http/httpserver_reentrant_finish_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(httpserver_reentrant_finish_test HttpServer)
  target_link_options(httpserver_reentrant_finish_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=bufferpoolGetLargeBufferSize"
  )
  target_link_libraries(httpserver_reentrant_finish_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests httpserver_reentrant_finish_test)

  add_waterwall_unit_test(
    waterwall.httpserver_reentrant_finish_unit
    httpserver_reentrant_finish_test
    "unit;tunnels;httpserver;reentrant;finish;line"
  )

  waterwall_add_native_executable(httpserver_split_callback_boundary_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/http/httpserver_split_callback_boundary_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(httpserver_split_callback_boundary_test HttpServer)
  target_link_options(httpserver_split_callback_boundary_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(httpserver_split_callback_boundary_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests httpserver_split_callback_boundary_test)

  add_waterwall_unit_test(
    waterwall.httpserver_split_callback_boundary_unit
    httpserver_split_callback_boundary_test
    "unit;tunnels;httpserver;split;backpressure;line"
  )
endif()

if(TARGET HalfDuplexClient)
  waterwall_add_native_executable(halfduplexclient_framing_random_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/halfduplex/halfduplexclient_framing_random_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(halfduplexclient_framing_random_test HalfDuplexClient)
  target_link_options(halfduplexclient_framing_random_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(halfduplexclient_framing_random_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests halfduplexclient_framing_random_test)

  add_waterwall_unit_test(
    waterwall.halfduplexclient_framing_random_unit
    halfduplexclient_framing_random_test
    "unit;tunnels;halfduplexclient;framing;id;random"
  )

  waterwall_add_native_executable(halfduplexclient_reentrant_close_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/halfduplex/halfduplexclient_reentrant_close_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(halfduplexclient_reentrant_close_test HalfDuplexClient)
  target_link_options(halfduplexclient_reentrant_close_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(halfduplexclient_reentrant_close_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests halfduplexclient_reentrant_close_test)

  add_waterwall_unit_test(
    waterwall.halfduplexclient_reentrant_close_unit
    halfduplexclient_reentrant_close_test
    "unit;tunnels;halfduplexclient;flow;reentrant;finish;lifetime;ownership"
  )
endif()

if(TARGET HalfDuplexServer)
  waterwall_add_native_executable(halfduplexserver_reentrant_init_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/halfduplex/halfduplexserver_reentrant_init_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(halfduplexserver_reentrant_init_test HalfDuplexServer)
  target_compile_definitions(halfduplexserver_reentrant_init_test PRIVATE
    WW_HALFDUPLEXSERVER_RENDEZVOUS_TEST_SEAM=1
  )
  target_link_options(halfduplexserver_reentrant_init_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=lineScheduleTask"
    "-Wl,--wrap=sbufAppendMerge"
    "-Wl,--wrap=bufferqueueTryPushBack"
  )
  target_link_libraries(halfduplexserver_reentrant_init_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests halfduplexserver_reentrant_init_test)

  add_waterwall_unit_test(
    waterwall.halfduplexserver_reentrant_init_unit
    halfduplexserver_reentrant_init_test
    "unit;tunnels;halfduplexserver;reentrant;init;line"
  )
endif()

if(TARGET SpeedLimit)
  waterwall_add_native_executable(speedlimit_line_failure_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/speedlimit/speedlimit_line_failure_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(speedlimit_line_failure_test SpeedLimit)
  target_link_options(speedlimit_line_failure_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=wtimerAdd"
  )
  target_link_libraries(speedlimit_line_failure_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests speedlimit_line_failure_test)

  add_waterwall_unit_test(
    waterwall.speedlimit_line_failure_unit
    speedlimit_line_failure_test
    "unit;tunnels;speedlimit;failure;line"
  )
endif()

if(TARGET Disturber)
  waterwall_add_native_executable(disturber_packet_lifecycle_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/disturber/disturber_packet_lifecycle_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(disturber_packet_lifecycle_test Disturber)
  target_link_options(disturber_packet_lifecycle_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
  )
  target_link_libraries(disturber_packet_lifecycle_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests disturber_packet_lifecycle_test)

  add_waterwall_unit_test(
    waterwall.disturber_packet_lifecycle_unit
    disturber_packet_lifecycle_test
    "unit;tunnels;disturber;packet;finish;lifecycle;affinity;ownership"
  )
endif()

if(TARGET JunkDatagramSender)
  waterwall_add_native_executable(junkdatagramsender_packet_lifecycle_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/junk/junkdatagramsender_packet_lifecycle_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(junkdatagramsender_packet_lifecycle_test JunkDatagramSender)
  target_link_options(junkdatagramsender_packet_lifecycle_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
  )
  target_link_libraries(junkdatagramsender_packet_lifecycle_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests junkdatagramsender_packet_lifecycle_test)

  add_waterwall_unit_test(
    waterwall.junkdatagramsender_packet_lifecycle_unit
    junkdatagramsender_packet_lifecycle_test
    "unit;tunnels;junkdatagramsender;packet;finish;delayed;buffers;ownership"
  )
endif()

if(TARGET SpeedTestServer)
  waterwall_add_native_executable(speedtestserver_schedule_rejection_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/speedtest/speedtestserver_schedule_rejection_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(speedtestserver_schedule_rejection_test SpeedTestServer)
  target_link_options(speedtestserver_schedule_rejection_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=lineScheduleTask"
    "-Wl,--wrap=lineScheduleDelayedTask"
  )
  target_link_libraries(speedtestserver_schedule_rejection_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests speedtestserver_schedule_rejection_test)

  add_waterwall_unit_test(
    waterwall.speedtestserver_schedule_rejection_unit
    speedtestserver_schedule_rejection_test
    "unit;tunnels;speedtestserver;scheduling;reentrant;lifetime;ownership"
  )
endif()

if(TARGET ConnectionFisherClient)
  waterwall_add_native_executable(connectionfisherclient_reentrant_selection_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/connectionfisher/connectionfisherclient_reentrant_selection_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(connectionfisherclient_reentrant_selection_test ConnectionFisherClient)
  target_link_options(connectionfisherclient_reentrant_selection_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
  )
  target_link_libraries(connectionfisherclient_reentrant_selection_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests connectionfisherclient_reentrant_selection_test)

  add_waterwall_unit_test(
    waterwall.connectionfisherclient_reentrant_selection_unit
    connectionfisherclient_reentrant_selection_test
    "unit;tunnels;connectionfisherclient;reentrant;lifetime;ownership"
  )
endif()

if(TARGET TlsServer)
  waterwall_add_native_executable(tlsserver_line_failure_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tlsserver_line_failure_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(tlsserver_line_failure_test TlsServer)
  target_link_options(tlsserver_line_failure_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=wtimerAdd"
    "-Wl,--wrap=BIO_new"
    "-Wl,--wrap=BIO_free"
    "-Wl,--wrap=SSL_new"
  )
  target_link_libraries(tlsserver_line_failure_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests tlsserver_line_failure_test)

  add_waterwall_unit_test(
    waterwall.tlsserver_line_failure_unit
    tlsserver_line_failure_test
    "unit;tunnels;tlsserver;failure;line"
  )
endif()

# Delayed fallback branches keep a line-task reference, not the borrowed line's
# logical lifetime.  Compile each affected server into its own fixture so the
# test can intercept delayed task admission without adding a production seam.
if(LINUX AND TARGET VlessServer)
  waterwall_add_native_executable(vlessserver_fallback_finish_lifetime_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/vless/vlessserver_fallback_finish_lifetime_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(vlessserver_fallback_finish_lifetime_test VlessServer)
  target_link_options(vlessserver_fallback_finish_lifetime_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=lineScheduleDelayedTask"
  )
  target_link_libraries(vlessserver_fallback_finish_lifetime_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests vlessserver_fallback_finish_lifetime_test)
  add_waterwall_unit_test(
    waterwall.vlessserver_fallback_finish_lifetime_unit
    vlessserver_fallback_finish_lifetime_test
    "unit;tunnels;vlessserver;fallback;finish;lifetime;reentrant;ownership;sanitizer"
  )
endif()

if(LINUX AND TARGET TrojanServer)
  waterwall_add_native_executable(trojanserver_fallback_finish_lifetime_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/trojan/trojanserver_fallback_finish_lifetime_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(trojanserver_fallback_finish_lifetime_test TrojanServer)
  target_link_options(trojanserver_fallback_finish_lifetime_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=lineScheduleDelayedTask"
  )
  target_link_libraries(trojanserver_fallback_finish_lifetime_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests trojanserver_fallback_finish_lifetime_test)
  add_waterwall_unit_test(
    waterwall.trojanserver_fallback_finish_lifetime_unit
    trojanserver_fallback_finish_lifetime_test
    "unit;tunnels;trojanserver;fallback;finish;lifetime;reentrant;ownership;sanitizer"
  )
endif()

if(LINUX AND TARGET TlsServer)
  waterwall_add_native_executable(tlsserver_sni_fallback_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tlsserver_sni_fallback_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(tlsserver_sni_fallback_test TlsServer)
  target_compile_definitions(tlsserver_sni_fallback_test PRIVATE
    TLSSERVER_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    TLSSERVER_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_options(tlsserver_sni_fallback_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=lineScheduleDelayedTask"
  )
  target_link_libraries(tlsserver_sni_fallback_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests tlsserver_sni_fallback_test)
  add_waterwall_unit_test(waterwall.tlsserver_sni_fallback_unit tlsserver_sni_fallback_test
    "unit;tunnels;tlsserver;fallback;ownership")
endif()

if(LINUX AND TARGET TlsServer)
  waterwall_add_native_executable(tlsserver_fallback_finish_lifetime_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tlsserver_fallback_finish_lifetime_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(tlsserver_fallback_finish_lifetime_test TlsServer)
  target_link_options(tlsserver_fallback_finish_lifetime_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=lineScheduleDelayedTask"
  )
  target_link_libraries(tlsserver_fallback_finish_lifetime_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests tlsserver_fallback_finish_lifetime_test)
  add_waterwall_unit_test(
    waterwall.tlsserver_fallback_finish_lifetime_unit
    tlsserver_fallback_finish_lifetime_test
    "unit;tunnels;tlsserver;fallback;finish;lifetime;reentrant;ownership;sanitizer"
  )
endif()

if(LINUX AND TARGET MuxServer AND TARGET VlessServer)
  waterwall_add_native_executable(muxserver_vless_fallback_finish_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/mux/muxserver_vless_fallback_finish_test.c)
  target_include_directories(muxserver_vless_fallback_finish_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/MuxServer/include
    ${CMAKE_SOURCE_DIR}/tunnels/VlessServer/include
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/MuxCommon/include
  )
  target_link_options(muxserver_vless_fallback_finish_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=lineScheduleDelayedTask"
  )
  target_link_libraries(muxserver_vless_fallback_finish_test PRIVATE MuxServer VlessServer ww)
  add_dependencies(waterwall_unit_tests muxserver_vless_fallback_finish_test)
  add_waterwall_unit_test(
    waterwall.muxserver_vless_fallback_finish_unit
    muxserver_vless_fallback_finish_test
    "unit;tunnels;muxserver;vlessserver;fallback;finish;lifetime;reentrant;ownership;sanitizer"
  )
endif()

if(TARGET TlsClient)
  waterwall_add_native_executable(tlsclient_line_failure_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tlsclient_line_failure_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(tlsclient_line_failure_test TlsClient)
  target_include_directories(tlsclient_line_failure_test BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
  )
  target_compile_definitions(tlsclient_line_failure_test PRIVATE BORINGSSL_PREFIX=WW_BSSL)
  target_link_options(tlsclient_line_failure_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=WW_BSSL_BIO_new"
    "-Wl,--wrap=WW_BSSL_BIO_free"
    "-Wl,--wrap=WW_BSSL_SSL_new"
    "-Wl,--wrap=WW_BSSL_SSL_add_application_settings"
  )
  target_link_libraries(tlsclient_line_failure_test PRIVATE StreamFragmenter ww ssl crypto)
  add_dependencies(waterwall_unit_tests tlsclient_line_failure_test)

  add_waterwall_unit_test(
    waterwall.tlsclient_line_failure_unit
    tlsclient_line_failure_test
    "unit;tunnels;tlsclient;failure;line"
  )
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
    waterwall_add_native_executable(tlsclient_fragment_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tlsclient_fragment_test.c)
    waterwall_line_failure_test_use_tunnel(tlsclient_fragment_test TlsClient)
    target_include_directories(tlsclient_fragment_test BEFORE PRIVATE
      ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include)
    target_link_options(tlsclient_fragment_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS}
      "-Wl,--wrap=nodemanagerGetConfigNodeByHash" "-Wl,--wrap=nodemanagerCreateTunnelInstance"
      "-Wl,--wrap=WW_BSSL_SSL_CTX_new" "-Wl,--wrap=WW_BSSL_BIO_new" "-Wl,--wrap=WW_BSSL_BIO_write"
      "-Wl,--wrap=WW_BSSL_X509_STORE_add_cert" "-Wl,--wrap=WW_BSSL_SSL_CTX_add_cert_compression_alg")
    target_link_libraries(tlsclient_fragment_test PRIVATE StreamFragmenter ww ssl crypto)
    add_dependencies(waterwall_unit_tests tlsclient_fragment_test)
    add_waterwall_unit_test(waterwall.tlsclient_fragment_unit tlsclient_fragment_test
      "unit;tunnels;tlsclient;fragmenter;configuration;lifetime")
  endif()
endif()

if(LINUX)
  foreach(tcp_side Listener Connector)
    if(TARGET Tcp${tcp_side})
      string(TOLOWER "${tcp_side}" tcp_side_lower)
      set(tcp_pause_target "tcp${tcp_side_lower}_pause_close_test")
      waterwall_add_native_executable(${tcp_pause_target} SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tcp/tcp_adapter_pause_close_test.c
        ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_budget.c
        ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_queue.c)
      if(tcp_side STREQUAL "Listener")
        target_compile_definitions(${tcp_pause_target} PRIVATE TCP_PAUSE_TEST_LISTENER=1)
        target_link_options(${tcp_pause_target} PRIVATE "-Wl,--wrap=socketacceptresultDestroy")
      else()
        target_link_options(${tcp_pause_target} PRIVATE "-Wl,--wrap=lineResolveDomainServiceAsync")
      endif()
      target_link_options(${tcp_pause_target} PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS} "-Wl,--wrap=send")
      target_link_libraries(${tcp_pause_target} PRIVATE Tcp${tcp_side} ww)
      add_dependencies(waterwall_unit_tests ${tcp_pause_target})
      add_waterwall_unit_test(
        waterwall.tcp${tcp_side_lower}_pause_close_unit
        ${tcp_pause_target}
        "unit;tunnels;tcp;pause;splice;lifetime"
      )
    endif()
  endforeach()
endif()

if(TARGET TcpUdpConnector AND TARGET TcpConnector AND TARGET UdpConnector)
  waterwall_add_native_executable(tcpudpconnector_selection_failure_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tcpudp/tcpudpconnector_selection_failure_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(tcpudpconnector_selection_failure_test TcpUdpConnector)
  target_link_options(tcpudpconnector_selection_failure_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(tcpudpconnector_selection_failure_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests tcpudpconnector_selection_failure_test)

  add_waterwall_unit_test(
    waterwall.tcpudpconnector_selection_failure_unit
    tcpudpconnector_selection_failure_test
    "unit;tunnels;tcpudpconnector;failure;line"
  )
endif()

if(TARGET Router)
  waterwall_add_native_executable(router_evaluation_failure_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/router/router_evaluation_failure_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(router_evaluation_failure_test Router)
  # Per-source properties are directory scoped, so Router's own relaxation for the STC regex implementation unit
  # has to be repeated where the source is compiled.
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set_source_files_properties(${CMAKE_SOURCE_DIR}/tunnels/Router/common/stc_regex.c
      PROPERTIES COMPILE_OPTIONS "-Wno-nested-externs")
  endif()
  target_link_options(router_evaluation_failure_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=MMDB_lookup_sockaddr"
    "-Wl,--wrap=MMDB_get_value"
    # cregex_match_sv() is a macro; cregex_match_opt() is the symbol it actually links against.
    "-Wl,--wrap=cregex_match_opt"
  )
  target_link_libraries(router_evaluation_failure_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests router_evaluation_failure_test)

  add_waterwall_unit_test(
    waterwall.router_evaluation_failure_unit
    router_evaluation_failure_test
    "unit;tunnels;router;failure;line"
  )
endif()

foreach(tcpoverudp_side Client Server)
  string(TOLOWER "${tcpoverudp_side}" tcpoverudp_side_lower)
  set(tcpoverudp_target "TcpOverUdp${tcpoverudp_side}")
  set(tcpoverudp_test "tcpoverudp${tcpoverudp_side_lower}_line_failure_test")

  if(TARGET ${tcpoverudp_target})
    waterwall_add_native_executable(${tcpoverudp_test} SOURCES "${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tcp_over_udp/${tcpoverudp_test}.c"
      ${WATERWALL_LINE_FAILURE_WW_SOURCES})
    waterwall_line_failure_test_use_tunnel(${tcpoverudp_test} ${tcpoverudp_target})
    # ikcp.h and ww_fec.h are private to the tunnel target but reachable from its public structure.h.
    target_include_directories(${tcpoverudp_test} PRIVATE
      ${CMAKE_SOURCE_DIR}/tunnels/${tcpoverudp_target}/kcp
      ${CMAKE_SOURCE_DIR}/tunnels/TcpOverUdpClient/fec
    )
    target_link_options(${tcpoverudp_test} PRIVATE
      ${WATERWALL_LINE_FAILURE_WRAPS}
      "-Wl,--wrap=wtimerAdd"
      "-Wl,--wrap=wtimerDelete"
      "-Wl,--wrap=ikcp_create"
      "-Wl,--wrap=ikcp_release"
      "-Wl,--wrap=tcpoverudpFecEncoderCreate"
      "-Wl,--wrap=tcpoverudpFecDecoderCreate"
      "-Wl,--wrap=tcpoverudpFecEncoderDestroy"
      "-Wl,--wrap=tcpoverudpFecDecoderDestroy"
    )
    target_link_libraries(${tcpoverudp_test} PRIVATE ww)
    add_dependencies(waterwall_unit_tests ${tcpoverudp_test})

    add_waterwall_unit_test(
      waterwall.${tcpoverudp_test}_unit
      ${tcpoverudp_test}
      "unit;tunnels;tcpoverudp;failure;line"
    )
  endif()
endforeach()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TARGET AuthenticationServer)
  waterwall_add_native_executable(authenticationserver_audit_config_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authenticationserver_audit_config_test.c)
  target_link_libraries(authenticationserver_audit_config_test PRIVATE AuthenticationServer ww)
  target_link_options(authenticationserver_audit_config_test PRIVATE "-Wl,--wrap=nodemanagerConfigName")
  add_dependencies(waterwall_unit_tests authenticationserver_audit_config_test)
  add_waterwall_unit_test(waterwall.authenticationserver_audit_config_unit authenticationserver_audit_config_test
    "unit;authentication;audit;configuration;security")
  waterwall_add_native_executable(authenticationserver_audit_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authenticationserver_audit_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  target_link_libraries(authenticationserver_audit_test PRIVATE AuthenticationServer ww)
  target_link_options(authenticationserver_audit_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=authenticationserverAuditWriterAppend" "-Wl,--wrap=authenticationserverSaveDatabaseLockedForReason")
  add_dependencies(waterwall_unit_tests authenticationserver_audit_test)
  add_waterwall_unit_test(waterwall.authenticationserver_audit_unit authenticationserver_audit_test
    "unit;authentication;audit;security;concurrency;tsan")
  waterwall_add_native_executable(authenticationserver_audit_writer_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authenticationserver_audit_writer_test.c)
  target_link_libraries(authenticationserver_audit_writer_test PRIVATE AuthenticationServer ww)
  target_link_options(authenticationserver_audit_writer_test PRIVATE
    "-Wl,--wrap=fwrite" "-Wl,--wrap=fflush" "-Wl,--wrap=rename" "-Wl,--wrap=fclose")
  add_dependencies(waterwall_unit_tests authenticationserver_audit_writer_test)
  add_waterwall_unit_test(waterwall.authenticationserver_audit_writer_unit authenticationserver_audit_writer_test
    "unit;authentication;audit;storage;security")
  waterwall_add_native_executable(authenticationserver_password_api_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authenticationserver_password_api_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  target_link_libraries(authenticationserver_password_api_test PRIVATE AuthenticationServer ww)
  target_link_options(authenticationserver_password_api_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=getHRTimeUs" "-Wl,--wrap=sendWorkerMessageForceQueueWithCleanup"
    "-Wl,--wrap=wCryptoSHA224" "-Wl,--wrap=wCryptoSHA256" "-Wl,--wrap=wCryptoX25519")
  add_dependencies(waterwall_unit_tests authenticationserver_password_api_test)
  add_waterwall_unit_test(waterwall.authenticationserver_password_api_unit authenticationserver_password_api_test
    "unit;authentication;api;security;ownership;concurrency;tsan")
  waterwall_add_native_executable(authenticationserver_create_api_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authenticationserver_create_api_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  target_link_libraries(authenticationserver_create_api_test PRIVATE AuthenticationServer ww)
  target_link_options(authenticationserver_create_api_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=getHRTimeUs" "-Wl,--wrap=sendWorkerMessageForceQueueWithCleanup"
    "-Wl,--wrap=pthread_rwlock_init" "-Wl,--wrap=wCryptoSHA224"
    "-Wl,--wrap=wCryptoSHA256" "-Wl,--wrap=wCryptoX25519")
  add_dependencies(waterwall_unit_tests authenticationserver_create_api_test)
  add_waterwall_unit_test(waterwall.authenticationserver_create_api_unit authenticationserver_create_api_test
    "unit;authentication;api;security;ownership;concurrency;tsan")
  waterwall_add_native_executable(authenticationserver_update_api_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authenticationserver_update_api_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  target_link_libraries(authenticationserver_update_api_test PRIVATE AuthenticationServer ww)
  target_link_options(authenticationserver_update_api_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=getHRTimeUs" "-Wl,--wrap=sendWorkerMessageForceQueueWithCleanup")
  add_dependencies(waterwall_unit_tests authenticationserver_update_api_test)
  add_waterwall_unit_test(waterwall.authenticationserver_update_api_unit authenticationserver_update_api_test
    "unit;authentication;api;security;ownership;concurrency;tsan")
  waterwall_add_native_executable(authenticationserver_api_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authenticationserver_api_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  target_link_libraries(authenticationserver_api_test PRIVATE AuthenticationServer ww)
  target_link_options(authenticationserver_api_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS} "-Wl,--wrap=getHRTimeUs")
  add_dependencies(waterwall_unit_tests authenticationserver_api_test)
  add_waterwall_unit_test(waterwall.authenticationserver_api_unit authenticationserver_api_test
    "unit;authentication;api;security;ownership")
  waterwall_add_native_executable(authenticationserver_storage_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authenticationserver_storage_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  target_include_directories(authenticationserver_storage_test PRIVATE ${CMAKE_SOURCE_DIR}/tunnels/AuthenticationServer)
  target_link_libraries(authenticationserver_storage_test PRIVATE AuthenticationServer ww)
  target_link_options(authenticationserver_storage_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=open" "-Wl,--wrap=fread" "-Wl,--wrap=fwrite" "-Wl,--wrap=fflush" "-Wl,--wrap=fclose"
    "-Wl,--wrap=fsync" "-Wl,--wrap=fchmod" "-Wl,--wrap=rename" "-Wl,--wrap=close"
    "-Wl,--wrap=getHRTimeUs" "-Wl,--wrap=time" "-Wl,--wrap=memoryFree"
    "-Wl,--wrap=cJSON_ParseWithLengthOpts" "-Wl,--wrap=cJSON_PrintBuffered")
  add_dependencies(waterwall_unit_tests authenticationserver_storage_test)
  add_waterwall_unit_test(waterwall.authenticationserver_storage_unit authenticationserver_storage_test
    "unit;authentication;storage")
  waterwall_add_native_executable(authenticationserver_responses_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authenticationserver_responses_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  target_link_libraries(authenticationserver_responses_test PRIVATE AuthenticationServer ww)
  target_link_options(authenticationserver_responses_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=sbufCreateWithPadding" "-Wl,--wrap=memoryFree" "-Wl,--wrap=configLexicalParseBoundedQuiet"
    "-Wl,--wrap=cJSON_PrintPreallocated" "-Wl,--wrap=cJSON_AddStringToObject" "-Wl,--wrap=cJSON_SetValuestring")
  add_dependencies(waterwall_unit_tests authenticationserver_responses_test)
  add_waterwall_unit_test(waterwall.authenticationserver_responses_unit authenticationserver_responses_test
    "unit;authentication;buffer;line")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TARGET AuthenticationClient)
  if(TARGET AuthenticationServer)
  waterwall_add_native_executable(authentication_numeric_settings_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authentication_numeric_settings_test.c)
  target_link_libraries(authentication_numeric_settings_test PRIVATE AuthenticationClient AuthenticationServer ww)
  add_dependencies(waterwall_unit_tests authentication_numeric_settings_test)
  add_waterwall_unit_test(waterwall.authentication_numeric_settings_unit authentication_numeric_settings_test
    "unit;authentication;configuration")
  waterwall_add_native_executable(authentication_sync_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authentication_sync_test.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authentication_sync_peer.c)
  target_link_libraries(authentication_sync_test PRIVATE AuthenticationClient AuthenticationServer ww)
  if(TARGET UserController)
    target_sources(authentication_sync_test PRIVATE
      ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authentication_sync_controller.c)
    target_link_libraries(authentication_sync_test PRIVATE UserController)
    target_compile_definitions(authentication_sync_test PRIVATE AUTHENTICATION_SYNC_HAVE_CONTROLLER=1)
  endif()
  target_link_options(authentication_sync_test PRIVATE "-Wl,--wrap=gettimeofday" "-Wl,--wrap=getHRTimeUs" "-Wl,--wrap=usersSnapshotAccounting" "-Wl,--wrap=fastRand32")
  add_dependencies(waterwall_unit_tests authentication_sync_test)
  # The 4097-account boundary exercises software X25519 under ASan as well.
  add_waterwall_unit_test(waterwall.authentication_sync_unit authentication_sync_test "unit;authentication;accounting;worker;line" 300)
  waterwall_add_native_executable(authentication_ingress_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authentication_ingress_test.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authentication_sync_peer.c)
  target_link_libraries(authentication_ingress_test PRIVATE AuthenticationClient AuthenticationServer ww)
  target_link_options(authentication_ingress_test PRIVATE "-Wl,--wrap=getHRTimeUs" "-Wl,--wrap=fastRand32")
  add_dependencies(waterwall_unit_tests authentication_ingress_test)
  add_waterwall_unit_test(waterwall.authentication_ingress_unit authentication_ingress_test
    "unit;authentication;buffer;line" 180)
  endif()
  waterwall_add_native_executable(authenticationclient_progress_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authenticationclient_progress_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  target_link_libraries(authenticationclient_progress_test PRIVATE AuthenticationClient ww)
  target_link_options(authenticationclient_progress_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=getHRTimeUs" "-Wl,--wrap=fastRand32" "-Wl,--wrap=cJSON_PrintUnformatted" "-Wl,--wrap=cJSON_Delete" "-Wl,--wrap=cJSON_free")
  add_dependencies(waterwall_unit_tests authenticationclient_progress_test)
  add_waterwall_unit_test(waterwall.authenticationclient_progress_unit authenticationclient_progress_test
    "unit;authentication;timer;worker;line")
  waterwall_add_native_executable(authenticationclient_profile_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authenticationclient_profile_test.c)
  target_link_libraries(authenticationclient_profile_test PRIVATE AuthenticationClient ww)
  target_link_options(authenticationclient_profile_test PRIVATE "-Wl,--wrap=stringDuplicate" "-Wl,--wrap=memoryFree")
  add_dependencies(waterwall_unit_tests authenticationclient_profile_test)
  add_waterwall_unit_test(waterwall.authenticationclient_profile_unit authenticationclient_profile_test
    "unit;authenticationclient;identity;allocation")
endif()

foreach(uot_side Client Server)
  if(TARGET UdpOverTcp${uot_side})
    string(TOLOWER "${uot_side}" uot_lower)
    set(uot_test "udpovertcp${uot_lower}_large_payload_test")
    waterwall_add_native_executable(${uot_test} SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/udp_over_tcp/udp_over_tcp_large_payload_test.c ${WATERWALL_LINE_FAILURE_WW_SOURCES})
    target_link_libraries(${uot_test} PRIVATE UdpOverTcp${uot_side} ww)
    target_link_options(${uot_test} PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
    if(uot_side STREQUAL "Server")
      target_compile_definitions(${uot_test} PRIVATE TEST_UOT_SERVER=1)
    endif()
    add_dependencies(waterwall_unit_tests ${uot_test})
    add_waterwall_unit_test(waterwall.udpovertcp${uot_lower}_large_payload_unit ${uot_test} "unit;tunnels;framing;udp;tcp")
  endif()
endforeach()

if(TARGET ReverseServer)
  waterwall_add_native_executable(reverseserver_splice_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/reverse/reverseserver_splice_test.c)
  target_link_libraries(reverseserver_splice_test PRIVATE ReverseServer ww)
  target_include_directories(reverseserver_splice_test PRIVATE ${CMAKE_SOURCE_DIR}/tunnels/ReverseClient/include)
  target_link_options(reverseserver_splice_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  add_dependencies(waterwall_unit_tests reverseserver_splice_test)
  add_waterwall_unit_test(waterwall.reverseserver_splice_unit reverseserver_splice_test "unit;tunnels;reverse;splice;lifetime")

  waterwall_add_native_executable(reverseserver_large_wait_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/reverse/reverseserver_large_wait_test.c)
  target_link_libraries(reverseserver_large_wait_test PRIVATE ReverseServer ww)
  target_include_directories(reverseserver_large_wait_test PRIVATE ${CMAKE_SOURCE_DIR}/tunnels/ReverseClient/include)
  target_link_options(reverseserver_large_wait_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  add_dependencies(waterwall_unit_tests reverseserver_large_wait_test)
  add_waterwall_unit_test(waterwall.reverseserver_large_wait_unit reverseserver_large_wait_test "unit;tunnels;reverse;buffering")
endif()

