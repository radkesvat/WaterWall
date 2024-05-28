

add_library(TrojanSocksServer STATIC
      trojan_socks_server.c
)

#ww api
target_include_directories(TrojanSocksServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../ww)
target_include_directories(TrojanSocksServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../tunnels/)
target_link_libraries(TrojanSocksServer ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_compile_definitions(TrojanSocksServer PRIVATE TrojanSocksServer_VERSION=0.1)
