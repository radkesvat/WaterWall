
add_library(ObfuscatorClient STATIC
                    instance/create.c
                    instance/api.c
                    instance/node.c
                    instance/chain.c
                    instance/index.c
                    common/helpers.c
                    common/line_state.c
                    upstream/payload.c
                    downstream/payload.c

                    common/obfs/xor.c
  
)

target_include_directories(ObfuscatorClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(ObfuscatorClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/ObfuscatorClient)

target_link_libraries(ObfuscatorClient ww)
if(NOT APPLE)
    target_precompile_headers(ObfuscatorClient REUSE_FROM ww)
endif()