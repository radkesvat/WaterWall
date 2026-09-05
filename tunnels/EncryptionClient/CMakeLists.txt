
add_library(EncryptionClient STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    common/helpers.c
                    common/line_state.c
                    upstream/init.c
                    upstream/est.c
                    upstream/fin.c
                    upstream/payload.c
                    upstream/est.c
                    downstream/init.c
                    downstream/fin.c
                    downstream/payload.c
  
)

target_include_directories(EncryptionClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(EncryptionClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/EncryptionClient)

target_link_libraries(EncryptionClient ww)
if(NOT APPLE)
    target_precompile_headers(EncryptionClient REUSE_FROM ww)
endif()
