
add_library(Disturber STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/stop.c
                    instance/chain.c
                    instance/index.c
                    common/helpers.c
                    common/line_state.c
                    upstream/init.c
                    upstream/fin.c
                    upstream/payload.c
                    downstream/init.c
                    downstream/fin.c
                    downstream/payload.c
  
)

target_include_directories(Disturber PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(Disturber PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/Disturber)

target_link_libraries(Disturber ww)
if(NOT APPLE)
    target_precompile_headers(Disturber REUSE_FROM ww)
endif()
