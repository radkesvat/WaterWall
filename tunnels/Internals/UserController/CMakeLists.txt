if(NOT TARGET AuthenticationClient)
    message(STATUS "Skipping UserController because AuthenticationClient target is unavailable")
    return()
endif()

add_library(UserController STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/stop.c
                    common/helpers.c
                    common/line_state.c
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

target_include_directories(UserController PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../AuthenticationClient/include
)

target_include_directories(UserController PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(UserController PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/UserController)

target_link_libraries(UserController PRIVATE ww AuthenticationClient)
if(NOT APPLE)
    target_precompile_headers(UserController REUSE_FROM ww)
endif()
