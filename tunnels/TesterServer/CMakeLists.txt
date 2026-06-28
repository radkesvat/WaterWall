add_library(TesterServer STATIC
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

target_include_directories(TesterServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(TesterServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/TesterServer)

target_link_libraries(TesterServer ww)
if(NOT APPLE)
    target_precompile_headers(TesterServer REUSE_FROM ww)
endif()
