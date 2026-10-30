add_library(PacketGenerator STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/stop.c
                    common/helpers.c
                    common/line_state.c
                    downstream/init.c
                    downstream/est.c
                    downstream/fin.c
                    downstream/payload.c
                    downstream/pause.c
                    downstream/resume.c
)

target_include_directories(PacketGenerator PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(PacketGenerator PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/PacketGenerator)

target_link_libraries(PacketGenerator ww)
if(NOT APPLE)
    target_precompile_headers(PacketGenerator REUSE_FROM ww)
endif()
