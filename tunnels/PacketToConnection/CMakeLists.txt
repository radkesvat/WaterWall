
add_library(PacketToConnection STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/chain.c
                    instance/index.c
                    common/helpers.c
                    common/line_state.c
                    common/tcp.c
                    common/udp.c
                    upstream/init.c
                    upstream/est.c
                    upstream/fin.c
                    upstream/payload.c
                    upstream/pause.c
                    upstream/resume.c
                    upstream/est.c
                    downstream/init.c
                    downstream/est.c
                    downstream/fin.c
                    downstream/payload.c
                    downstream/pause.c
                    downstream/resume.c
                    downstream/est.c
  
)

target_include_directories(PacketToConnection PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(PacketToConnection PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/)

# in this moduel we get this warring, but we assert that the alignment is correct
# it is also checkable with UBSAN
if(NOT MSVC)
    target_compile_options(PacketToConnection PRIVATE -Wno-address-of-packed-member)
endif()

target_link_libraries(PacketToConnection ww)


