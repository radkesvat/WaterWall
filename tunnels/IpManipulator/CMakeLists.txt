
add_library(IpManipulator STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/stop.c
                    instance/chain.c
                    instance/index.c
                    common/flow_table.c
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
                    common/tricks/firstsni/trick.c
                    common/tricks/overlapsni/trick.c
                    common/tricks/smugglefin/trick.c
                    common/tricks/smugglesni/trick.c
                    common/tricks/synfinsni/trick.c
                    common/tricks/echsnitrick/trick.c
                    common/tricks/sniblender/trick.c
                    common/tricks/tcpbitchange/trick.c
                    common/tricks/portghost/trick.c
  
)

target_include_directories(IpManipulator PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(IpManipulator PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/IpManipulator)

# common/ is PUBLIC because the public structure.h includes common/flow_table.h.
target_include_directories(IpManipulator PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/common/)
target_include_directories(IpManipulator PRIVATE ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include)


target_link_libraries(IpManipulator ww TlsClient)
if(NOT APPLE)
    target_precompile_headers(IpManipulator REUSE_FROM ww)
endif()
