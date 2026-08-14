
add_library(ConnectionToPackets STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/start.c
                    instance/pre_stop.c
                    instance/stop.c
                    instance/chain.c
                    common/helpers.c
                    common/line_state.c
                    common/drain.c
                    common/flow.c
                    common/frag.c
                    common/netif.c
                    common/tcp.c
                    common/udp.c
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

target_include_directories(ConnectionToPackets PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(ConnectionToPackets PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/ConnectionToPackets)
target_include_directories(ConnectionToPackets PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/)

# lwip packs its protocol headers; the alignment is asserted by construction here
# and is also checkable with UBSAN
if(NOT MSVC)
    target_compile_options(ConnectionToPackets PRIVATE -Wno-address-of-packed-member)
endif()

target_link_libraries(ConnectionToPackets ww)
target_link_libraries(ConnectionToPackets DomainResolver)
if(NOT APPLE)
    target_precompile_headers(ConnectionToPackets REUSE_FROM ww)
endif()
