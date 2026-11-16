add_library(Ping6Server STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    common/helpers.c
                    upstream/payload.c
                    downstream/payload.c
)

target_include_directories(Ping6Server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(Ping6Server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/Ping6Server)

target_link_libraries(Ping6Server PRIVATE PingCommon ww)
if(NOT APPLE)
    target_precompile_headers(Ping6Server REUSE_FROM ww)
endif()
