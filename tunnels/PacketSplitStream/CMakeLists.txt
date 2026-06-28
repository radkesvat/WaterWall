
add_library(PacketSplitStream STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/stop.c
                    instance/chain.c
                    common/helpers.c
                    common/line_state.c
                    upstream/init.c
                    upstream/payload.c
                    upstream/fin.c
                    upstream/noop.c
                    downstream/payload.c
                    downstream/fin.c
                    downstream/noop.c
)

target_include_directories(PacketSplitStream PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(PacketSplitStream PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/PacketSplitStream)

target_link_libraries(PacketSplitStream ww)
if(NOT APPLE)
    target_precompile_headers(PacketSplitStream REUSE_FROM ww)
endif()
