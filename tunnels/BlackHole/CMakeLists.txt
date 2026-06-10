add_library(BlackHole STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/stop.c
                    instance/api.c
                    instance/node.c
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

target_include_directories(BlackHole PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_include_directories(BlackHole PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(BlackHole PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/BlackHole)

target_link_libraries(BlackHole ww)
if(NOT APPLE)
    target_precompile_headers(BlackHole REUSE_FROM ww)
endif()
