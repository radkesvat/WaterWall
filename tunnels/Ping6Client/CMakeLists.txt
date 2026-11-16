add_library(Ping6Client STATIC
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

target_include_directories(Ping6Client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(Ping6Client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/Ping6Client)

target_link_libraries(Ping6Client PRIVATE PingCommon ww)
if(NOT APPLE)
    target_precompile_headers(Ping6Client REUSE_FROM ww)
endif()
