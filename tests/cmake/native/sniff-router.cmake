# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
if(TARGET SniffRouter)
  waterwall_add_native_executable(sniffrouter_classifier_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/router/sniffrouter_classifier_test.c)
  target_include_directories(sniffrouter_classifier_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/SniffRouter/include
    ${CMAKE_SOURCE_DIR}/tunnels/ReverseClient/include
  )
  target_link_libraries(sniffrouter_classifier_test PRIVATE SniffRouter ReverseClient ww)
  add_dependencies(waterwall_unit_tests sniffrouter_classifier_test)

  add_waterwall_unit_test(waterwall.sniffrouter_classifier_unit sniffrouter_classifier_test "unit;tunnels;sniffrouter")
endif()

if(TARGET SniffRouter AND TARGET Router)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    waterwall_add_native_executable(router_splice_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/router/router_splice_test.c)
    target_include_directories(router_splice_test PRIVATE
      ${CMAKE_SOURCE_DIR}/tunnels/Router
      ${CMAKE_SOURCE_DIR}/tunnels/ReverseClient/include
    )
    target_link_libraries(router_splice_test PRIVATE SniffRouter Router ww)
    target_link_options(router_splice_test PRIVATE "-Wl,--wrap=sbufDestroy" "-Wl,--wrap=bufferpoolReuseBuffer")
    add_dependencies(waterwall_unit_tests router_splice_test)
    add_waterwall_unit_test(
      waterwall.router_splice_unit
      router_splice_test
      "unit;tunnels;router;sniffrouter;splice;lifetime"
    )
  endif()

  waterwall_add_native_executable(router_chain_ownership_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/router/router_chain_ownership_test.c)
  target_include_directories(router_chain_ownership_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/SniffRouter/include
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include
    ${CMAKE_SOURCE_DIR}/tunnels/Router
  )
  target_link_libraries(router_chain_ownership_test PRIVATE SniffRouter Router ReverseClient ww)
  add_dependencies(waterwall_unit_tests router_chain_ownership_test)

  add_waterwall_unit_test(
    waterwall.router_chain_ownership_unit
    router_chain_ownership_test
    "unit;tunnels;router;sniffrouter;chain;ownership"
  )
endif()

