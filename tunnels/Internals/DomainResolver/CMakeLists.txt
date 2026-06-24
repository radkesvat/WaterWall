add_library(DomainResolver STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
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

target_include_directories(DomainResolver PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(DomainResolver PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(DomainResolver PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/DomainResolver)

target_link_libraries(DomainResolver ww)
if(NOT APPLE)
    target_precompile_headers(DomainResolver REUSE_FROM ww)
endif()
