
add_library(TunDevice STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/start.c
                    instance/stop.c
                    common/dns.c
                    common/helpers.c
                    common/routes.c
)

target_include_directories(TunDevice PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(TunDevice PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/TunDevice)

target_link_libraries(TunDevice ww)
if(NOT APPLE)
    target_precompile_headers(TunDevice REUSE_FROM ww)
endif()
