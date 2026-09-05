
add_library(ObfuscatorServer STATIC
                    instance/create.c
                    instance/api.c
                    instance/node.c
                    common/helpers.c
                    common/line_state.c
                    upstream/payload.c
                    downstream/payload.c

                    common/obfs/xor.c
  
)

target_include_directories(ObfuscatorServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(ObfuscatorServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/ObfuscatorServer)

target_link_libraries(ObfuscatorServer ww)
if(NOT APPLE)
    target_precompile_headers(ObfuscatorServer REUSE_FROM ww)
endif()
