add_library(PingServer STATIC
                    instance/create.c
                    instance/api.c
                    instance/node.c
)

target_include_directories(PingServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(PingServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/PingServer)

target_link_libraries(PingServer PRIVATE PingCommon ww)
if(NOT APPLE)
    target_precompile_headers(PingServer REUSE_FROM ww)
endif()
