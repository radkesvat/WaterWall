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

if(TARGET AuthenticationServer AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
  waterwall_add_native_executable(authenticationserver_api_concurrency_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authenticationserver_api_concurrency_test.c
    ${CMAKE_SOURCE_DIR}/ww/bufio/splice_stream.c
    ${CMAKE_SOURCE_DIR}/ww/bufio/splice_buffer.c
    ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_budget.c
    ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_queue.c
    ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_stream.c
    LIBRARIES AuthenticationServer ww
    INCLUDES ${CMAKE_SOURCE_DIR}/tunnels/AuthenticationServer
      ${CMAKE_SOURCE_DIR}/tunnels/AuthenticationServer/include/AuthenticationServer)
  target_link_options(authenticationserver_api_concurrency_test PRIVATE
    "-Wl,--wrap=abortProgramNow" "-Wl,--wrap=requestProgramShutdown"
    "-Wl,--wrap=bufferpoolGetLargeBuffer" "-Wl,--wrap=bufferpoolGetMediumBuffer"
    "-Wl,--wrap=bufferpoolGetSmallBuffer" "-Wl,--wrap=bufferpoolTryGetBestFit"
    "-Wl,--wrap=bufferpoolGetBestFit" "-Wl,--wrap=bufferpoolGetSpliceBuffer"
    "-Wl,--wrap=bufferpoolReuseBuffer" "-Wl,--wrap=sbufDestroy"
    "-Wl,--wrap=secureRandomBytes" "-Wl,--wrap=nodeApiRegister" "-Wl,--wrap=nodeApiUnregister")
  add_dependencies(waterwall_unit_tests authenticationserver_api_concurrency_test)
  add_waterwall_unit_test(waterwall.authenticationserver_api_concurrency_unit authenticationserver_api_concurrency_test
    "unit;api;authentication;concurrency;lifecycle;tsan")
endif()
