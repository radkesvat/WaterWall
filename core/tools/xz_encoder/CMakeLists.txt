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
target_include_directories(waterwall_xz_encoder PRIVATE "${waterwall_host_xz_SOURCE_DIR}/src/liblzma/api")

if(BUILD_TESTING)
  find_program(PYTHON_EXECUTABLE NAMES python3 python REQUIRED)
  add_test(NAME waterwall.packed_payload_generation
    COMMAND "${PYTHON_EXECUTABLE}" "${WATERWALL_SOURCE_DIR}/tests/packed_payload_test.py"
      --encoder "$<TARGET_FILE:waterwall_xz_encoder>")
  add_subdirectory("${WATERWALL_SOURCE_DIR}/ww/vendor/xz-embedded" xz-embedded)
  add_subdirectory("${WATERWALL_SOURCE_DIR}/ww/compression" decoder)
  add_library(xz_runtime_fixture MODULE runtime_fixture.c)
  set_target_properties(xz_runtime_fixture PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
  add_executable(xz_payload_test payload_test.c)
  target_link_libraries(xz_payload_test PRIVATE WaterWall::XZDecoder XZEmbedded::XZEmbedded)
  add_test(NAME waterwall.xz_payload_roundtrip
    COMMAND "${CMAKE_COMMAND}"
      "-DENCODER=$<TARGET_FILE:waterwall_xz_encoder>"
      "-DDECODER_TEST=$<TARGET_FILE:xz_payload_test>"
      "-DMODULE=$<TARGET_FILE:xz_runtime_fixture>"
      "-DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/roundtrip-$<CONFIG>"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/roundtrip.cmake")
  set_tests_properties(waterwall.xz_payload_roundtrip PROPERTIES TIMEOUT 120)
endif()
