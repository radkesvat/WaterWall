add_library(ObfuscatorClient STATIC
    instance/create.c
    instance/api.c
    instance/node.c
    common/line_state.c
    common/stream.c
    upstream/init.c
    downstream/init.c
    upstream/fin.c
    downstream/fin.c
    upstream/payload.c
    downstream/payload.c
)

target_include_directories(ObfuscatorClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(ObfuscatorClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/ObfuscatorClient)
target_link_libraries(ObfuscatorClient PUBLIC ObfuscatorCommon ww)
if(NOT APPLE)
    target_precompile_headers(ObfuscatorClient REUSE_FROM ww)
endif()
