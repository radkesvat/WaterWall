
add_library(WireGuard STATIC
      wireguard_client.c

)

target_link_libraries(WireGuard PUBLIC ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)


target_compile_definitions(WireGuard PRIVATE  WireGuard_VERSION=0.1)

