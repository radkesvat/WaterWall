# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
if(TARGET PacketsToStream)
  waterwall_add_native_executable(packetstostream_parser_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/packet_bridges/packetstostream_parser_test.c)
  target_include_directories(packetstostream_parser_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/PacketsToStream/include
  )
  target_link_libraries(packetstostream_parser_test PRIVATE PacketsToStream ww)
  add_dependencies(waterwall_unit_tests packetstostream_parser_test)

  add_waterwall_unit_test(waterwall.packetstostream_parser_unit packetstostream_parser_test "unit;tunnels;packetstostream")
endif()

if(TARGET ReverseClient AND UNIX)
  waterwall_add_native_executable(reverseclient_owner_drain_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/reverse/reverseclient_owner_drain_test.c)
  target_compile_definitions(reverseclient_owner_drain_test PRIVATE WW_IDLE_TABLE_TEST_SEAM=1)
  target_include_directories(reverseclient_owner_drain_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/ReverseClient/include
  )
  target_link_libraries(reverseclient_owner_drain_test PRIVATE ReverseClient ww)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(reverseclient_owner_drain_test PRIVATE "-Wl,--wrap=sbufDestroy" "-Wl,--wrap=bufferpoolReuseBuffer")
  endif()
  add_dependencies(waterwall_unit_tests reverseclient_owner_drain_test)
  add_waterwall_unit_test(
    waterwall.reverseclient_owner_drain_unit
    reverseclient_owner_drain_test
    "unit;tunnels;reverseclient;ownership;shutdown"
  )
endif()

