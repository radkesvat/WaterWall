
add_library(WireGuard STATIC
      wireguard_client.c

)

#ww api
target_include_directories(WireGuard PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(WireGuard PUBLIC ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)


target_compile_definitions(WireGuard PRIVATE  WireGuard_VERSION=0.1)

