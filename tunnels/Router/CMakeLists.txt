add_library(Router STATIC
    common/classifier.c
    common/line_state.c
    common/match_helpers.c
    common/rules.c
    modules/matchers.c
    modules/source_ips/source_ips.c
    modules/source_port/source_port.c
    modules/network/network.c
    modules/password/password.c
    modules/protocol/protocol.c
    modules/attributes/attributes.c
    modules/destination_ip/destination_ip.c
    modules/destination_domain/destination_domain.c
    modules/username/username.c
    modules/destination_port/destination_port.c
    downstream/est.c
    downstream/fin.c
    downstream/init.c
    downstream/pause.c
    downstream/payload.c
    downstream/resume.c
    instance/api.c
    instance/chain.c
    instance/create.c
    instance/destroy.c
    instance/index.c
    instance/node.c
    instance/prepair.c
    instance/start.c
    instance/stop.c
    upstream/est.c
    upstream/fin.c
    upstream/init.c
    upstream/pause.c
    upstream/payload.c
    upstream/resume.c
)

target_include_directories(Router PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(Router PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(Router PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/Router)

target_link_libraries(Router ww)
if(NOT APPLE)
    target_precompile_headers(Router REUSE_FROM ww)
endif()
