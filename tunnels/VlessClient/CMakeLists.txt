add_library(VlessClient STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/stop.c
                    instance/chain.c
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

target_include_directories(VlessClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_include_directories(VlessClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(VlessClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/VlessClient)

target_link_libraries(VlessClient ww DomainResolver)
if(NOT APPLE)
    target_precompile_headers(VlessClient REUSE_FROM ww)
endif()
