add_library(FakeTcpHeaderClient STATIC
    instance/create.c
    instance/node.c
    upstream/payload.c
    downstream/payload.c
)

target_include_directories(FakeTcpHeaderClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(FakeTcpHeaderClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/FakeTcpHeaderClient)
target_link_libraries(FakeTcpHeaderClient PUBLIC FakeTcpHeaderCommon ww)
if(NOT APPLE)
    target_precompile_headers(FakeTcpHeaderClient REUSE_FROM ww)
endif()
