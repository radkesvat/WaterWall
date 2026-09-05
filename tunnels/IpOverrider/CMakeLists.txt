
add_library(IpOverrider STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    common/helpers.c
                    common/line_state.c
                    upstream/payload.c
                    downstream/payload.c
  
)

target_include_directories(IpOverrider PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(IpOverrider PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/IpOverrider)

target_link_libraries(IpOverrider ww)
if(NOT APPLE)
    target_precompile_headers(IpOverrider REUSE_FROM ww)
endif()
