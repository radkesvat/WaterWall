# GameNetworkingSockets behind a C interface, and the WaterWall half shared by
# GnsClient and GnsServer.
#
# src/engine.cc is the only source that includes the library's headers. Like
# QuicCommon's engine it is C++ without ww's precompiled header, and it sees the
# library's own compile definitions; the C sources do not.
add_library(gns_engine OBJECT src/engine.cc)
target_include_directories(gns_engine PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(gns_engine PRIVATE WaterWall::Gns waterwall_cpu_options)
target_compile_features(gns_engine PRIVATE cxx_std_20)
set_target_properties(gns_engine PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
waterwall_configure_runtime_dependency(gns_engine)

add_library(GnsCommon STATIC src/settings.c src/port.c src/session.c src/endpoint.c
    $<TARGET_OBJECTS:gns_engine>)
target_include_directories(GnsCommon PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/transport)
target_link_libraries(GnsCommon PUBLIC ww PRIVATE $<LINK_ONLY:WaterWall::Gns>)
if(NOT APPLE)
    target_precompile_headers(GnsCommon REUSE_FROM ww)
endif()
