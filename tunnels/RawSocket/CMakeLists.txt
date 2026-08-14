
add_library(RawSocket STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/start.c
                    instance/stop.c
                    common/helpers.c
)

target_include_directories(RawSocket PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(RawSocket PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/RawSocket)

target_link_libraries(RawSocket ww)
if(NOT APPLE)
    target_precompile_headers(RawSocket REUSE_FROM ww)
endif()
