
add_library(Socks5Client STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/stop.c
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
                    downstream/init.c
                    downstream/est.c
                    downstream/fin.c
                    downstream/payload.c
                    downstream/pause.c
                    downstream/resume.c
  
)

target_include_directories(Socks5Client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(Socks5Client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/Socks5Client)

target_link_libraries(Socks5Client ww DomainResolver)
if(NOT APPLE)
    target_precompile_headers(Socks5Client REUSE_FROM ww)
endif()
