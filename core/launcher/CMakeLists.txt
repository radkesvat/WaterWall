set_target_properties(${WATERWALL_APPLICATION_TARGET} PROPERTIES
  OUTPUT_NAME "waterwall_application"
)

find_program(PYTHON3_EXECUTABLE NAMES python3 python REQUIRED)
if(NOT CMAKE_STRIP)
  find_program(CMAKE_STRIP NAMES strip REQUIRED)
endif()

set(WW_HOST_ENCODER_EXE "${PROJECT_SOURCE_DIR}/build/xz-encoder-host/Release/waterwall_xz_encoder")
# Let the independent native build check its own dependency graph on each build.
# Its driver serializes producers sharing the documented host cache.
add_custom_target(waterwall_host_encoder_target
  COMMAND "${PYTHON3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/core/build_host_encoder.py" "${CMAKE_COMMAND}"
  BYPRODUCTS "${WW_HOST_ENCODER_EXE}"
  WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
  COMMENT "Checking host XZ encoder"
  VERBATIM
)

set(WW_PACKED_PAYLOAD_C "${PROJECT_BINARY_DIR}/packed/$<CONFIG>/payload.c")
add_custom_command(
  OUTPUT "${WW_PACKED_PAYLOAD_C}"
  COMMAND "${PYTHON3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/core/generate_packed_payload.py"
    --executable "$<TARGET_FILE:${WATERWALL_APPLICATION_TARGET}>"
    --encoder "${WW_HOST_ENCODER_EXE}"
    --strip "${CMAKE_STRIP}"
    --output "${WW_PACKED_PAYLOAD_C}"
  DEPENDS ${WATERWALL_APPLICATION_TARGET} waterwall_host_encoder_target "${WW_HOST_ENCODER_EXE}"
    "${CMAKE_STRIP}" "${PROJECT_SOURCE_DIR}/core/generate_packed_payload.py"
  COMMENT "Generating packed Waterwall payload"
  VERBATIM
)

add_executable(Waterwall
  ${WATERWALL_STARTUP_GUARD_OBJECTS}
  main.c
  launcher_linux.c
  ${PROJECT_SOURCE_DIR}/core/startup_options.c
  ${PROJECT_SOURCE_DIR}/ww/node_builder/config_lexical.c
  ${PROJECT_SOURCE_DIR}/ww/vendor/cjson/cJSON.c
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
  "${PROJECT_SOURCE_DIR}/core"
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${PROJECT_SOURCE_DIR}/ww/node_builder"
  "${PROJECT_SOURCE_DIR}/ww/compression/include"
  "${PROJECT_SOURCE_DIR}/ww/vendor/xz-embedded/include"
  "${PROJECT_SOURCE_DIR}/ww/vendor/cjson"
  "${PROJECT_BINARY_DIR}/ww"
)

target_link_libraries(Waterwall PRIVATE WaterWall::XZDecoder m)
add_dependencies(Waterwall ${WATERWALL_APPLICATION_TARGET})
