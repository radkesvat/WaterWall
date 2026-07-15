add_library(RealityCommon STATIC
    reality_v2.c
)

target_include_directories(RealityCommon PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(RealityCommon PRIVATE ww)

if(NOT APPLE)
    target_precompile_headers(RealityCommon REUSE_FROM ww)
endif()
