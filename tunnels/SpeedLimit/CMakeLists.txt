add_library(SpeedLimit STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/stop.c
                    common/helpers.c
                    common/line_state.c
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

target_include_directories(SpeedLimit PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(SpeedLimit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/SpeedLimit)

target_link_libraries(SpeedLimit ww)
if(NOT APPLE)
    target_precompile_headers(SpeedLimit REUSE_FROM ww)
endif()
