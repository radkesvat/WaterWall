
add_library(IpManipulator STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/chain.c
                    instance/index.c
                    common/helpers.c
                    common/line_state.c
                    upstream/init.c
                    upstream/est.c
                    upstream/fin.c
                    upstream/payload.c
                    upstream/pause.c
                    upstream/resume.c
                    upstream/est.c
                    downstream/init.c
                    downstream/est.c
                    downstream/fin.c
                    downstream/payload.c
                    downstream/pause.c
                    downstream/resume.c
                    downstream/est.c
                    common/tricks/protoswap/trick.c
                    common/tricks/sniblender/trick.c
                    common/tricks/tcpbitchange/trick.c
  
)

target_include_directories(IpManipulator PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_include_directories(IpManipulator PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common/)


target_link_libraries(IpManipulator ww)
target_precompile_headers(IpManipulator REUSE_FROM ww)
