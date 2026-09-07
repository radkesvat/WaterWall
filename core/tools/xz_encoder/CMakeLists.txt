cmake_minimum_required(VERSION 3.25)
project(WaterWallXZEncoder LANGUAGES C)

# This independent project always uses the build machine's native compiler.
# Never inherit the production toolchain when cross-compiling Waterwall.
if(CMAKE_CROSSCOMPILING)
  message(FATAL_ERROR "Configure the XZ encoder with a native host compiler, without the target toolchain")
endif()
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
get_filename_component(WATERWALL_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
include(CTest)
include("${WATERWALL_SOURCE_DIR}/ww/cmake/CPM.cmake")
CPMAddPackage(
  NAME waterwall_host_xz
  GIT_REPOSITORY https://github.com/tukaani-project/xz.git
  GIT_TAG 4b73f2ec19a99ef465282fbce633e8deb33691b3 # v5.8.3
  OPTIONS
    "BUILD_TESTING OFF"
    "BUILD_SHARED_LIBS OFF"
    "XZ_TOOL_XZ OFF"
    "XZ_TOOL_XZDEC OFF"
    "XZ_TOOL_LZMADEC OFF"
    "XZ_TOOL_LZMAINFO OFF"
    "XZ_TOOL_SCRIPTS OFF"
    "XZ_NLS OFF"
    "XZ_DOC OFF"
    "XZ_THREADS no"
)
add_executable(waterwall_xz_encoder encoder.c)
set_target_properties(waterwall_xz_encoder PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>")
target_link_libraries(waterwall_xz_encoder PRIVATE liblzma)
# Upstream publishes API includes for installation, not its build-tree target.
target_include_directories(waterwall_xz_encoder PRIVATE "${waterwall_host_xz_SOURCE_DIR}/src/liblzma/api"
  "${WATERWALL_SOURCE_DIR}/ww/vendor/xz-embedded/include")

add_executable(waterwall_payload_tool payload_tool.c)
set_target_properties(waterwall_payload_tool PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>")
if(NOT WIN32)
  target_compile_definitions(waterwall_xz_encoder PRIVATE _FILE_OFFSET_BITS=64 _POSIX_C_SOURCE=200809L)
  target_compile_definitions(waterwall_payload_tool PRIVATE _FILE_OFFSET_BITS=64 _POSIX_C_SOURCE=200809L)
endif()

if(BUILD_TESTING)
  find_program(PYTHON_EXECUTABLE NAMES python3 python REQUIRED)
  add_test(NAME waterwall.packed_payload_generation
    COMMAND "${PYTHON_EXECUTABLE}" "${WATERWALL_SOURCE_DIR}/tests/packed_payload_test.py"
      --cmake "${CMAKE_COMMAND}" --encoder "$<TARGET_FILE:waterwall_xz_encoder>"
      --payload-tool "$<TARGET_FILE:waterwall_payload_tool>")
  # Exercise the ordinary and launcher decoder policies without building a launcher.
  set(WW_PACK_RUNTIME ON)
  add_subdirectory("${WATERWALL_SOURCE_DIR}/ww/vendor/xz-embedded" xz-embedded)
  add_subdirectory("${WATERWALL_SOURCE_DIR}/ww/compression" decoder)
  add_library(xz_runtime_fixture MODULE runtime_fixture.c)
  set_target_properties(xz_runtime_fixture PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
  foreach(decoder_policy xz xz_launcher)
    add_executable(${decoder_policy}_payload_test payload_test.c)
    target_include_directories(${decoder_policy}_payload_test PRIVATE
      "${WATERWALL_SOURCE_DIR}/ww/vendor/xz-embedded/include")
    if(decoder_policy STREQUAL "xz_launcher")
      target_link_libraries(${decoder_policy}_payload_test PRIVATE ww_launcher_xz_decoder)
      if(NOT WW_PACKED_PAYLOAD_CRC32)
        target_compile_definitions(${decoder_policy}_payload_test PRIVATE WW_TEST_SKIP_PAYLOAD_CRC32)
      endif()
    else()
      target_link_libraries(${decoder_policy}_payload_test PRIVATE WaterWall::XZDecoder)
    endif()
    add_test(NAME waterwall.${decoder_policy}_payload_roundtrip
      COMMAND "${CMAKE_COMMAND}"
        "-DENCODER=$<TARGET_FILE:waterwall_xz_encoder>"
        "-DDECODER_TEST=$<TARGET_FILE:${decoder_policy}_payload_test>"
        "-DMODULE=$<TARGET_FILE:xz_runtime_fixture>"
        "-DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/${decoder_policy}-roundtrip-$<CONFIG>"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/roundtrip.cmake")
    set_tests_properties(waterwall.${decoder_policy}_payload_roundtrip PROPERTIES TIMEOUT 120)
  endforeach()
endif()
