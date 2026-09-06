if(NOT WATERWALL_SOURCE_DIR)
  set(WATERWALL_SOURCE_DIR "${PROJECT_SOURCE_DIR}")
endif()
set_target_properties(${WATERWALL_APPLICATION_TARGET} PROPERTIES
  OUTPUT_NAME "waterwall_application"
)

find_program(PYTHON3_EXECUTABLE NAMES python3 python REQUIRED)
if(NOT MSVC AND NOT CMAKE_STRIP)
  find_program(CMAKE_STRIP NAMES strip REQUIRED)
endif()

set(host_generator "Ninja Multi-Config")
if(CMAKE_HOST_WIN32 AND MSVC AND CMAKE_GENERATOR MATCHES "^Visual Studio")
  # A VS generator initializes its native toolchain even outside a developer shell.
  set(host_generator "${CMAKE_GENERATOR}")
endif()
set(WW_HOST_ENCODER_GENERATOR "${host_generator}" CACHE STRING "Native encoder generator")
set(WW_HOST_C_COMPILER "" CACHE FILEPATH "Native compiler for the independent XZ encoder")
if(CMAKE_HOST_WIN32 AND WW_HOST_ENCODER_GENERATOR MATCHES "^Visual Studio")
  # The independent VS configure selects the native compiler itself. Windows
  # presets explicitly setting CMAKE_SYSTEM_NAME still report cross-compiling.
  set(WW_HOST_C_COMPILER "")
elseif(NOT WW_HOST_C_COMPILER)
  if(NOT CMAKE_CROSSCOMPILING OR (CMAKE_HOST_WIN32 AND WIN32))
    # Supported packed Windows targets are x86/x64 and run on the Windows
    # development host, including the native Ninja/MSVC and MSYS2 environments.
    set(WW_HOST_C_COMPILER "${CMAKE_C_COMPILER}")
  else()
    find_program(WW_NATIVE_CC NAMES cc clang gcc NO_CMAKE_FIND_ROOT_PATH REQUIRED)
    set(WW_HOST_C_COMPILER "${WW_NATIVE_CC}")
  endif()
endif()
string(SHA256 host_identity "${CMAKE_HOST_SYSTEM_NAME};${CMAKE_HOST_SYSTEM_PROCESSOR};${WW_HOST_C_COMPILER};${WW_HOST_ENCODER_GENERATOR}")
string(SUBSTRING "${host_identity}" 0 12 host_identity)
set(WW_HOST_ENCODER_BUILD "${WATERWALL_SOURCE_DIR}/build/xz-encoder-host-${host_identity}")
set(host_suffix "")
if(CMAKE_HOST_WIN32)
  set(host_suffix ".exe")
endif()
set(WW_HOST_ENCODER_EXE "${WW_HOST_ENCODER_BUILD}/Release/waterwall_xz_encoder${host_suffix}")
if(MSVC)
  set(finalization_args --finalization msvc)
  set(finalization_dependencies "")
else()
  set(finalization_args --finalization gnu --strip "${CMAKE_STRIP}")
  set(finalization_dependencies "${CMAKE_STRIP}")
endif()
# Let the independent native build check its own dependency graph on each build.
# Its driver serializes producers sharing the documented host cache.
add_custom_target(waterwall_host_encoder_target
  COMMAND "${PYTHON3_EXECUTABLE}" "${WATERWALL_SOURCE_DIR}/core/build_host_encoder.py" "${CMAKE_COMMAND}"
    --build-dir "${WW_HOST_ENCODER_BUILD}" --compiler "${WW_HOST_C_COMPILER}"
    --generator "${WW_HOST_ENCODER_GENERATOR}"
  BYPRODUCTS "${WW_HOST_ENCODER_EXE}"
  WORKING_DIRECTORY "${WATERWALL_SOURCE_DIR}"
  COMMENT "Checking host XZ encoder"
  VERBATIM
)

set(WW_PACKED_PAYLOAD_C "${PROJECT_BINARY_DIR}/packed/$<CONFIG>/payload.c")
add_custom_command(
  OUTPUT "${WW_PACKED_PAYLOAD_C}"
  COMMAND "${PYTHON3_EXECUTABLE}" "${WATERWALL_SOURCE_DIR}/core/generate_packed_payload.py"
    --executable "$<TARGET_FILE:${WATERWALL_APPLICATION_TARGET}>"
    --encoder "${WW_HOST_ENCODER_EXE}"
    ${finalization_args} --target "${WW_PACKED_TARGET}"
    --output "${WW_PACKED_PAYLOAD_C}"
  DEPENDS ${WATERWALL_APPLICATION_TARGET} waterwall_host_encoder_target "${WW_HOST_ENCODER_EXE}"
    ${finalization_dependencies} "${WATERWALL_SOURCE_DIR}/core/generate_packed_payload.py"
    "${WATERWALL_SOURCE_DIR}/core/build_host_encoder.py" "${CMAKE_CURRENT_LIST_FILE}"
  COMMENT "Generating packed Waterwall payload"
  VERBATIM
)

set(launcher_guard_objects "")
if(WW_USE_STARTUP_GUARD)
  set(launcher_guard_objects $<TARGET_OBJECTS:WaterwallLauncherStartupGuard>)
endif()
if(WIN32)
  set(launcher_backend launcher_windows.c)
else()
  set(launcher_backend launcher_linux.c)
endif()
add_executable(Waterwall
  ${launcher_guard_objects}
  main.c
  ${launcher_backend}
  ${WATERWALL_SOURCE_DIR}/core/startup_options.c
  ${WATERWALL_SOURCE_DIR}/ww/node_builder/config_lexical.c
  ${WATERWALL_SOURCE_DIR}/ww/vendor/cjson/cJSON.c
  "${WW_PACKED_PAYLOAD_C}"
)

set_target_properties(Waterwall PROPERTIES
  OUTPUT_NAME "Waterwall"
  RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/$<CONFIG>"
  UNITY_BUILD OFF
  DISABLE_PRECOMPILE_HEADERS ON
  LINKER_LANGUAGE C
)

if(WW_USE_STARTUP_GUARD)
  target_compile_definitions(Waterwall PRIVATE WATERWALL_HAS_STARTUP_GUARD=1)
endif()

target_compile_definitions(Waterwall PRIVATE
  WW_CJSON_CRT_ALLOCATOR=1
  WATERWALL_VERSION=${Waterwall_VERSION}
)

target_include_directories(Waterwall PRIVATE
  "${WATERWALL_SOURCE_DIR}/core"
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${WATERWALL_SOURCE_DIR}/ww/node_builder"
  "${WATERWALL_SOURCE_DIR}/ww/compression/include"
  "${WATERWALL_SOURCE_DIR}/ww/vendor/xz-embedded/include"
  "${WATERWALL_SOURCE_DIR}/ww/vendor/cjson"
  "${PROJECT_BINARY_DIR}/ww"
)

target_link_libraries(Waterwall PRIVATE ww_launcher_xz_decoder)
if(WIN32)
  target_compile_definitions(Waterwall PRIVATE _WIN32_WINNT=0x0600)
  target_link_libraries(Waterwall PRIVATE advapi32)
  if(MSVC)
    target_link_options(Waterwall PRIVATE /DYNAMICBASE /FIXED:NO /NXCOMPAT /INCREMENTAL:NO /DEBUG:NONE
      "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
      target_link_options(Waterwall PRIVATE /HIGHENTROPYVA)
    endif()
  else()
    target_sources(Waterwall PRIVATE $<TARGET_OBJECTS:waterwall_resources>)
    target_link_options(Waterwall PRIVATE "LINKER:--dynamicbase" "LINKER:--enable-reloc-section"
      "LINKER:--nxcompat" "LINKER:--strip-all")
  endif()
else()
  target_link_libraries(Waterwall PRIVATE m)
  target_link_options(Waterwall PRIVATE "LINKER:--strip-all")
endif()
add_dependencies(Waterwall ${WATERWALL_APPLICATION_TARGET})
