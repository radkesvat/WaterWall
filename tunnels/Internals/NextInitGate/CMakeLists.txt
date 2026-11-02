add_library(NextInitGate STATIC src/next_init_gate.c)

target_include_directories(NextInitGate PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(NextInitGate PRIVATE ww)

if(NOT APPLE)
    target_precompile_headers(NextInitGate REUSE_FROM ww)
endif()
