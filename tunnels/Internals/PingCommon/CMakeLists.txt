add_library(PingCommon STATIC
    src/ping_wire.c
)

target_include_directories(PingCommon PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(PingCommon PRIVATE ww)

if(NOT APPLE)
    target_precompile_headers(PingCommon REUSE_FROM ww)
endif()
