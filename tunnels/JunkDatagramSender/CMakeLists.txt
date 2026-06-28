
add_library(JunkDatagramSender STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/stop.c
                    common/helpers.c
                    common/settings.c
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
                    modules/dispatcher.c
                    modules/placeholder.c
                    modules/dns.c
                    modules/dhcp.c
                    modules/ntp.c
                    modules/quic_http3.c
                    modules/rtp_rtcp_srtp.c
                    modules/stun_turn_ice.c
                    modules/mdns.c
                    modules/snmp.c
                    modules/syslog.c
                    modules/ipsec_natt.c
                    modules/sip.c
                    modules/tftp.c
                    modules/ssdp.c
                    modules/radius.c
                    modules/gtpu.c
                    modules/game_udp_protocols.c
                    modules/coap.c
)

target_include_directories(JunkDatagramSender PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(JunkDatagramSender PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/JunkDatagramSender)
target_include_directories(JunkDatagramSender PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/modules)

target_link_libraries(JunkDatagramSender ww)
if(NOT APPLE)
    target_precompile_headers(JunkDatagramSender REUSE_FROM ww)
endif()
