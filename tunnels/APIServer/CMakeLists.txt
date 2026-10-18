add_library(APIServer STATIC
    common/access.c
    common/codec.c
    common/config.c
    common/flow.c
    common/input.c
    common/line_state.c
    common/output.c
    instance/create.c
    instance/destroy.c
    instance/node.c
    instance/prepair.c
    instance/stop.c
    upstream/fin.c
    upstream/init.c
    upstream/pause.c
    upstream/payload.c
    upstream/resume.c
)
target_include_directories(APIServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(APIServer ww)
if(NOT APPLE)
    target_precompile_headers(APIServer REUSE_FROM ww)
endif()
