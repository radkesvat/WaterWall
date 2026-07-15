add_library(RealityServer STATIC
    instance/create.c
    instance/destroy.c
    instance/api.c
    instance/node.c
    instance/prepair.c
    instance/start.c
    instance/stop.c
    instance/chain.c
    instance/index.c
    common/helpers.c
    common/line_state.c
    common/tls_binding.c
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

target_include_directories(RealityServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(RealityServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/RealityServer)
target_link_libraries(RealityServer PRIVATE ww RealityCommon)

if(NOT APPLE)
    target_precompile_headers(RealityServer REUSE_FROM ww)
endif()
