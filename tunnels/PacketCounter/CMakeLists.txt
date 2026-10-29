add_library(PacketCounter STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
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

target_include_directories(PacketCounter PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(PacketCounter PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/PacketCounter)

target_link_libraries(PacketCounter ww)
if(NOT APPLE)
    target_precompile_headers(PacketCounter REUSE_FROM ww)
endif()
