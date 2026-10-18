if(TARGET APIServer)
  waterwall_add_native_executable(apiserver_config_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/api/config_test.c)
  target_link_libraries(apiserver_config_test PRIVATE APIServer ww)
  add_dependencies(waterwall_unit_tests apiserver_config_test)
  add_waterwall_unit_test(waterwall.apiserver_config_unit apiserver_config_test
    "unit;api;configuration")
  waterwall_add_native_executable(apiserver_codec_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/api/codec_test.c)
  target_link_libraries(apiserver_codec_test PRIVATE APIServer ww)
  add_dependencies(waterwall_unit_tests apiserver_codec_test)
  add_waterwall_unit_test(waterwall.apiserver_codec_unit apiserver_codec_test
    "unit;api;codec;portable")
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    waterwall_add_native_executable(apiserver_session_test SUPPORT SOURCES
      ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/api/session_test.c)
    target_link_libraries(apiserver_session_test PRIVATE APIServer ww)
    target_link_options(apiserver_session_test PRIVATE
      "-Wl,--wrap=getHRTimeUs" "-Wl,--wrap=wtimerAdd"
      "-Wl,--wrap=sendWorkerMessageForceQueueWithCleanup" "-Wl,--wrap=nodemanagerResolveApiTarget")
    add_dependencies(waterwall_unit_tests apiserver_session_test)
    add_waterwall_unit_test(waterwall.apiserver_session_unit apiserver_session_test
      "unit;api;lifetime")
  endif()
  if(TARGET TcpOverUdpClient AND TARGET TcpOverUdpServer AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    waterwall_add_native_executable(apiserver_reliable_stream_test SUPPORT SOURCES
      ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/api/reliable_stream_test.c)
    target_link_libraries(apiserver_reliable_stream_test PRIVATE APIServer TcpOverUdpClient TcpOverUdpServer ww)
    target_link_options(apiserver_reliable_stream_test PRIVATE "-Wl,--wrap=nodemanagerResolveApiTarget")
    add_dependencies(waterwall_unit_tests apiserver_reliable_stream_test)
    add_waterwall_unit_test(waterwall.apiserver_reliable_stream_unit apiserver_reliable_stream_test
      "unit;api;tcpoverudp;lifetime")
  endif()
endif()
