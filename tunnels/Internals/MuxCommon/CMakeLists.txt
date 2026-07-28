add_library(MuxCommon STATIC
    src/mux_wire.c
)

target_include_directories(MuxCommon PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(MuxCommon PRIVATE ww)

if(NOT APPLE)
    target_precompile_headers(MuxCommon REUSE_FROM ww)
endif()
