add_library(LoggerTunnel STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/stop.c
                    instance/api.c
                    instance/node.c
                    common/helpers.c
                    upstream/init.c
                    upstream/est.c
                    upstream/fin.c
                    upstream/payload.c
                    upstream/pause.c
                    upstream/resume.c
                    downstream/init.c
                    downstream/est.c
                    downstream/fin.c
                    downstream/payload.c
                    downstream/pause.c
                    downstream/resume.c
)

target_include_directories(LoggerTunnel PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(LoggerTunnel PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(LoggerTunnel PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/LoggerTunnel)

target_link_libraries(LoggerTunnel ww)
if(NOT APPLE)
    target_precompile_headers(LoggerTunnel REUSE_FROM ww)
endif()
