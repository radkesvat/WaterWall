add_library(RtmpClient STATIC
    instance/create.c
    instance/node.c
    common/output.c
    common/settings.c
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
target_include_directories(RtmpClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(RtmpClient PUBLIC ww PRIVATE RtmpTunnelCommon)
if(NOT APPLE)
    target_precompile_headers(RtmpClient REUSE_FROM ww)
endif()
