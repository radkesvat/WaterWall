set(ENET_VENDOR_DIR ${CMAKE_SOURCE_DIR}/ww/vendor/enet)

# Vendored ENet protocol core, byte-identical to the pinned upstream commit (see
# ww/vendor/enet/README.waterwall.md). Upstream's socket layer is never compiled
# here: src/platform.c supplies ENet's platform functions, so ENet cannot
# create, poll or close an OS socket. Like kcp_protocol, the core links only the
# runtime options and not ww, so it keeps its own warning set.
add_library(enet_protocol OBJECT
    ${ENET_VENDOR_DIR}/callbacks.c
    ${ENET_VENDOR_DIR}/host.c
    ${ENET_VENDOR_DIR}/list.c
    ${ENET_VENDOR_DIR}/packet.c
    ${ENET_VENDOR_DIR}/peer.c
    ${ENET_VENDOR_DIR}/protocol.c)
target_include_directories(enet_protocol PUBLIC ${ENET_VENDOR_DIR}/include)
target_compile_definitions(enet_protocol PRIVATE ENET_BUILDING_LIB=1)
target_link_libraries(enet_protocol PRIVATE waterwall_runtime_options)
# Upstream sources share file-local helper names.
set_target_properties(enet_protocol PROPERTIES UNITY_BUILD OFF)

add_library(EnetCommon STATIC src/platform.c src/driver.c $<TARGET_OBJECTS:enet_protocol>)
target_include_directories(EnetCommon PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(EnetCommon SYSTEM PUBLIC ${ENET_VENDOR_DIR}/include)
target_include_directories(EnetCommon PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(EnetCommon PUBLIC ww)
# Built without ww's precompiled header: these sources need only wdef.h, and the
# WaterWall API headers define helpers that call the OS (wproc.h's execCmd uses
# poll). The archive must reference no OS socket function in any configuration.
set_target_properties(EnetCommon PROPERTIES DISABLE_PRECOMPILE_HEADERS ON)

# WaterWall half shared by EnetClient and EnetServer: the node settings, the worker session around the driver and
# the tunnel logic of both roles. It uses the WaterWall API, so it is a separate archive from the checked EnetCommon.
add_library(EnetTunnelCommon STATIC src/settings.c src/session.c src/endpoint.c)
target_link_libraries(EnetTunnelCommon PUBLIC EnetCommon PRIVATE ww)
if(NOT APPLE)
    target_precompile_headers(EnetTunnelCommon REUSE_FROM ww)
endif()
