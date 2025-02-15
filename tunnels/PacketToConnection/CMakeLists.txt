
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
                    common/ip4_input_nat.c
                    common/ip4_prerouting_hook.c
                    common/nat_proto_icmp4.c
                    common/nat_proto_ip4.c
                    common/nat_proto_tcp.c
                    common/nat_proto_udp.c
                    common/nat.c
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

# in this moduel we get this warring, but we assert that the alignment is correct

if(NOT MSVC)
    target_compile_options(PacketToConnection PRIVATE -Wno-address-of-packed-member)
endif()

target_link_libraries(PacketToConnection ww)


