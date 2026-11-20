set(WW_RTMP_REVISION c0463893bc509e65bea9f4f76be68c1f89ccdfcf)
CPMAddPackage(
    NAME waterwall_media_server
    GIT_REPOSITORY https://github.com/ireader/media-server.git
    GIT_TAG ${WW_RTMP_REVISION}
    GIT_CONFIG core.autocrlf=false
    DOWNLOAD_ONLY TRUE
)
if(NOT waterwall_media_server_SOURCE_DIR)
    message(FATAL_ERROR "The pinned ireader/media-server source is required for RTMP")
endif()

find_package(Git REQUIRED)
set(WW_RTMP_PATCHES
    ${CMAKE_CURRENT_SOURCE_DIR}/patches/0001-bounded-waterwall-profile.patch)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${WW_RTMP_PATCHES})
set(WW_RTMP_SOURCE_DIR "${CMAKE_BINARY_DIR}/patched-deps/media-server")
set(WW_RTMP_PATCH_STAMP "${WW_RTMP_SOURCE_DIR}/.waterwall-patch-stamp")
set(WW_RTMP_EXPECTED_STAMP "${WW_RTMP_REVISION}\n")
foreach(patch IN LISTS WW_RTMP_PATCHES)
    file(SHA256 "${patch}" patch_sha256)
    string(APPEND WW_RTMP_EXPECTED_STAMP "${patch_sha256}\n")
endforeach()
if(EXISTS "${WW_RTMP_PATCH_STAMP}")
    file(READ "${WW_RTMP_PATCH_STAMP}" WW_RTMP_CURRENT_STAMP)
endif()
if(NOT "${WW_RTMP_CURRENT_STAMP}" STREQUAL "${WW_RTMP_EXPECTED_STAMP}")
    file(REMOVE_RECURSE "${WW_RTMP_SOURCE_DIR}")
    file(MAKE_DIRECTORY "${WW_RTMP_SOURCE_DIR}/libflv/include" "${WW_RTMP_SOURCE_DIR}/libflv/source")
    file(COPY "${waterwall_media_server_SOURCE_DIR}/librtmp" "${waterwall_media_server_SOURCE_DIR}/LICENSE"
        DESTINATION "${WW_RTMP_SOURCE_DIR}")
    file(COPY "${waterwall_media_server_SOURCE_DIR}/libflv/include/amf0.h"
        DESTINATION "${WW_RTMP_SOURCE_DIR}/libflv/include")
    file(COPY "${waterwall_media_server_SOURCE_DIR}/libflv/source/amf0.c"
        DESTINATION "${WW_RTMP_SOURCE_DIR}/libflv/source")
    foreach(patch IN LISTS WW_RTMP_PATCHES)
        execute_process(
            COMMAND "${CMAKE_COMMAND}" -E env "GIT_CEILING_DIRECTORIES=${CMAKE_BINARY_DIR}"
                "${GIT_EXECUTABLE}" apply --whitespace=nowarn "${patch}"
            WORKING_DIRECTORY "${WW_RTMP_SOURCE_DIR}"
            COMMAND_ERROR_IS_FATAL ANY)
    endforeach()
    file(WRITE "${WW_RTMP_PATCH_STAMP}" "${WW_RTMP_EXPECTED_STAMP}")
endif()

set(WW_RTMP_PROTOCOL_SOURCES "${WW_RTMP_SOURCE_DIR}/librtmp/source")
add_library(rtmp_protocol STATIC
    "${WW_RTMP_SOURCE_DIR}/libflv/source/amf0.c"
    "${WW_RTMP_PROTOCOL_SOURCES}/rtmp-chunk-header.c"
    "${WW_RTMP_PROTOCOL_SOURCES}/rtmp-chunk-read.c"
    "${WW_RTMP_PROTOCOL_SOURCES}/rtmp-chunk-write.c"
    "${WW_RTMP_PROTOCOL_SOURCES}/rtmp-client.c"
    "${WW_RTMP_PROTOCOL_SOURCES}/rtmp-control-handler.c"
    "${WW_RTMP_PROTOCOL_SOURCES}/rtmp-control-message.c"
    "${WW_RTMP_PROTOCOL_SOURCES}/rtmp-event.c"
    "${WW_RTMP_PROTOCOL_SOURCES}/rtmp-handler.c"
    "${WW_RTMP_PROTOCOL_SOURCES}/rtmp-handshake.c"
    "${WW_RTMP_PROTOCOL_SOURCES}/rtmp-invoke-handler.c"
    "${WW_RTMP_PROTOCOL_SOURCES}/rtmp-netconnection.c"
    "${WW_RTMP_PROTOCOL_SOURCES}/rtmp-netstream.c"
    "${WW_RTMP_PROTOCOL_SOURCES}/rtmp-server.c"
    engine/ww-rtmp-engine.c)
target_include_directories(rtmp_protocol PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/engine")
target_include_directories(rtmp_protocol PRIVATE
    "${WW_RTMP_SOURCE_DIR}/librtmp/include" "${WW_RTMP_SOURCE_DIR}/libflv/include"
    "${PROJECT_SOURCE_DIR}/ww/libc")
target_link_libraries(rtmp_protocol PRIVATE waterwall_runtime_options "$<LINK_ONLY:ww>")
target_compile_options(rtmp_protocol PRIVATE
    $<$<AND:$<CONFIG:Debug>,$<BOOL:${ENABLE_ASAN}>>:-fsanitize=address>
    $<$<AND:$<CONFIG:Debug>,$<BOOL:${ENABLE_TSAN}>>:-fsanitize=thread>
    $<$<AND:$<CONFIG:Debug>,$<BOOL:${ENABLE_LSAN}>>:-fsanitize=leak>
    $<$<AND:$<CONFIG:Debug>,$<BOOL:${ENABLE_USAN}>>:-fsanitize=undefined>)
set_target_properties(rtmp_protocol PROPERTIES UNITY_BUILD OFF DISABLE_PRECOMPILE_HEADERS ON)

add_library(rtmp_session STATIC rtmp_session.c rtmp_credit.c rtmp_wire.c)
target_include_directories(rtmp_session PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rtmp_session PRIVATE ww rtmp_protocol)

add_library(RtmpTunnelCommon STATIC rtmp_tunnel.c rtmp_settings.c)
target_include_directories(RtmpTunnelCommon PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(RtmpTunnelCommon PUBLIC ww PRIVATE rtmp_session)
if(NOT APPLE)
    target_precompile_headers(RtmpTunnelCommon REUSE_FROM ww)
endif()
