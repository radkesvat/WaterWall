add_library(PingClient STATIC
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

target_include_directories(PingClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(PingClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/PingClient)

target_link_libraries(PingClient PRIVATE PingCommon ww)
if(NOT APPLE)
    target_precompile_headers(PingClient REUSE_FROM ww)
endif()
