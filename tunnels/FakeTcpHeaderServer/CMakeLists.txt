add_library(FakeTcpHeaderServer STATIC
    instance/create.c
    instance/node.c
    upstream/payload.c
    downstream/payload.c
)

target_include_directories(FakeTcpHeaderServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(FakeTcpHeaderServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/FakeTcpHeaderServer)
target_link_libraries(FakeTcpHeaderServer PUBLIC FakeTcpHeaderCommon ww)
if(NOT APPLE)
    target_precompile_headers(FakeTcpHeaderServer REUSE_FROM ww)
endif()
