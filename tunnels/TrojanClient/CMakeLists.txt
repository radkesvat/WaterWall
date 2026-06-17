add_library(TrojanClient STATIC
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

target_include_directories(TrojanClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_include_directories(TrojanClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(TrojanClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/TrojanClient)

target_link_libraries(TrojanClient ww)
if(NOT APPLE)
    target_precompile_headers(TrojanClient REUSE_FROM ww)
endif()
