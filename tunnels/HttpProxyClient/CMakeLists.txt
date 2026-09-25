add_library(HttpProxyClient STATIC
    instance/chain.c instance/create.c instance/node.c instance/api.c instance/destroy.c instance/stop.c
    common/settings.c common/request.c common/lifecycle.c common/flow.c
    upstream/init.c upstream/payload.c upstream/fin.c upstream/pause.c upstream/resume.c
    downstream/est.c downstream/payload.c downstream/fin.c downstream/pause.c downstream/resume.c)
target_include_directories(HttpProxyClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(HttpProxyClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/HttpProxyClient)
target_link_libraries(HttpProxyClient PUBLIC HttpProxyCommon PRIVATE DomainResolver ww)
if(NOT APPLE)
    target_precompile_headers(HttpProxyClient REUSE_FROM ww)
endif()
