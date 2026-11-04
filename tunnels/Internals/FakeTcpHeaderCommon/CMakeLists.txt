add_library(FakeTcpHeaderCommon STATIC
    src/faketcpheader_settings.c
    src/faketcpheader_wire.c
    src/faketcpheader_encryption.c
)

target_include_directories(FakeTcpHeaderCommon PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(FakeTcpHeaderCommon PRIVATE ww)

if(NOT APPLE)
    target_precompile_headers(FakeTcpHeaderCommon REUSE_FROM ww)
endif()
