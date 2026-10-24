add_library(VmessServer STATIC
    instance/create.c
    instance/destroy.c
    instance/api.c
    instance/node.c
    instance/chain.c
    instance/prepair.c
    common/input.c
    common/fallback.c
    common/replay.c
    common/auth.c
    common/flow.c
    common/lifecycle.c
    common/protocol.c
    common/udp.c
    common/line_state.c
    upstream/init.c
    upstream/fin.c
    upstream/payload.c
    upstream/pause.c
    upstream/resume.c
    downstream/est.c
    downstream/fin.c
    downstream/payload.c
    downstream/pause.c
    downstream/resume.c
)

if(NOT TARGET AuthenticationClient)
    message(FATAL_ERROR "VmessServer requires AuthenticationClient; enable INCLUDE_AUTHENTICATION_CLIENT")
endif()

if(NOT TARGET UserController)
    message(FATAL_ERROR "VmessServer requires UserController; enable INCLUDE_USER_CONTROLLER")
endif()

target_include_directories(VmessServer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../AuthenticationClient/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../Internals/UserController/include
)
target_include_directories(VmessServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(VmessServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/VmessServer)

target_link_libraries(VmessServer PRIVATE ww AuthenticationClient UserController)
target_link_libraries(VmessServer PUBLIC VmessCommon)
if(NOT APPLE)
    target_precompile_headers(VmessServer REUSE_FROM ww)
endif()
