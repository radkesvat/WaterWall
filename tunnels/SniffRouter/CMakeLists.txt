add_library(SniffRouter STATIC
    sniffrouter.c
)

target_include_directories(SniffRouter PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(SniffRouter ww)
if(NOT APPLE)
    target_precompile_headers(SniffRouter REUSE_FROM ww)
endif()
