add_library(PacketReceiver STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/stop.c
                    instance/chain.c
                    instance/index.c
                    common/helpers.c
                    upstream/init.c
                    upstream/est.c
                    upstream/fin.c
                    upstream/payload.c
                    upstream/pause.c
                    upstream/resume.c
                    downstream/init.c
                    downstream/est.c
                    downstream/fin.c
                    downstream/payload.c
                    downstream/pause.c
                    downstream/resume.c
)

target_include_directories(PacketReceiver PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(PacketReceiver PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/PacketReceiver)

target_link_libraries(PacketReceiver ww)
if(NOT APPLE)
    target_precompile_headers(PacketReceiver REUSE_FROM ww)
endif()
