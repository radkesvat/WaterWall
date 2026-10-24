add_library(VmessClient STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/chain.c
                    common/destination.c
                    common/protocol.c
                    common/input.c
                    common/flow.c
                    common/lifecycle.c
                    common/line_state.c
                    upstream/init.c
                    upstream/fin.c
                    upstream/payload.c
                    upstream/pause.c
                    upstream/resume.c
                    downstream/est.c
                    downstream/fin.c
                    downstream/payload.c
                    downstream/pause.c
                    downstream/resume.c

)

target_include_directories(VmessClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(VmessClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/VmessClient)

target_link_libraries(VmessClient ww DomainResolver VmessCommon)
if(NOT APPLE)
    target_precompile_headers(VmessClient REUSE_FROM ww)
endif()
