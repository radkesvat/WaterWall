add_library(kcp_protocol OBJECT kcp/ikcp.c)
target_include_directories(kcp_protocol PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/kcp)
target_link_libraries(kcp_protocol PRIVATE waterwall_runtime_options)

add_library(kcp_fec OBJECT
    fec/ww_fec.cc fec/fec.cc fec/reedsolomon.cc fec/matrix.cc
    fec/galois.cc fec/galois_noasm.cc fec/inversion_tree.cc)
target_compile_features(kcp_fec PRIVATE cxx_std_17)
target_include_directories(kcp_fec PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/fec PRIVATE ${CMAKE_SOURCE_DIR}/ww/libc)
target_link_libraries(kcp_fec PRIVATE waterwall_runtime_options)

add_library(KcpCommon STATIC src/wire.c src/session.c
    $<TARGET_OBJECTS:kcp_protocol> $<TARGET_OBJECTS:kcp_fec>)
target_include_directories(KcpCommon PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/kcp ${CMAKE_CURRENT_SOURCE_DIR}/fec)
target_link_libraries(KcpCommon PUBLIC ww)
if(NOT APPLE)
    target_precompile_headers(KcpCommon REUSE_FROM ww)
endif()
