add_library(RtmpServer STATIC
    instance/create.c
    instance/node.c
    common/output.c
    upstream/init.c
    upstream/payload.c
    upstream/fin.c
    upstream/pause.c
    upstream/resume.c
    downstream/est.c
    downstream/payload.c
    downstream/fin.c
    downstream/pause.c
    downstream/resume.c
)
target_include_directories(RtmpServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(RtmpServer PUBLIC ww PRIVATE RtmpTunnelCommon)
if(NOT APPLE)
    target_precompile_headers(RtmpServer REUSE_FROM ww)
endif()
