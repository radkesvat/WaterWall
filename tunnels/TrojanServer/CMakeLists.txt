add_library(TrojanServer STATIC
    instance/create.c
    instance/destroy.c
    instance/api.c
    instance/node.c
    instance/chain.c
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

if(NOT TARGET AuthenticationClient)
    message(FATAL_ERROR "TrojanServer requires AuthenticationClient; enable INCLUDE_AUTHENTICATION_CLIENT")
endif()

if(NOT TARGET UserController)
    message(FATAL_ERROR "TrojanServer requires UserController; enable INCLUDE_USER_CONTROLLER")
endif()

target_include_directories(TrojanServer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../AuthenticationClient/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../Internals/UserController/include
)

target_include_directories(TrojanServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(TrojanServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/TrojanServer)

target_link_libraries(TrojanServer PRIVATE ww AuthenticationClient UserController)
if(NOT APPLE)
    target_precompile_headers(TrojanServer REUSE_FROM ww)
endif()
