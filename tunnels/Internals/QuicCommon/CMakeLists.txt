add_library(quic_node_runtime OBJECT config.c context.c flow.c input.c timer.c)
target_link_libraries(quic_node_runtime PRIVATE ww)
target_include_directories(quic_node_runtime PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(quic_node_runtime PROPERTIES UNITY_BUILD OFF)

add_library(QuicCommon STATIC quic_engine.cc carrier.c $<TARGET_OBJECTS:quic_node_runtime>)
target_include_directories(QuicCommon PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(QuicCommon PRIVATE ${PROJECT_SOURCE_DIR}/ww/utils)
target_link_libraries(QuicCommon PRIVATE WaterWall::Quiche WaterWall::BoringSSL)
target_compile_features(QuicCommon PRIVATE cxx_std_20)
set_target_properties(QuicCommon PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
waterwall_configure_runtime_dependency(QuicCommon)
target_link_libraries(QuicCommon PRIVATE waterwall_cpu_options)

# Only the separate C object target sees application/OpenSSL headers. QUICHE's
# C++ translation unit sees the prefixed BoringSSL provider exclusively.
