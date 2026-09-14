add_library(HttpProxyServer STATIC
    instance/create.c instance/node.c instance/api.c instance/chain.c instance/prepair.c
    instance/stop.c instance/destroy.c common/parser.c common/helpers.c
    upstream/init.c upstream/fin.c upstream/payload.c upstream/pause.c upstream/resume.c
    downstream/est.c downstream/fin.c downstream/payload.c downstream/pause.c downstream/resume.c)
if(NOT TARGET AuthenticationClient OR NOT TARGET UserController)
    message(FATAL_ERROR "HttpProxyServer requires AuthenticationClient and UserController")
endif()
target_include_directories(HttpProxyServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(HttpProxyServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/HttpProxyServer)
target_link_libraries(HttpProxyServer PRIVATE ww AuthenticationClient UserController)
if(NOT APPLE)
    target_precompile_headers(HttpProxyServer REUSE_FROM ww)
endif()
