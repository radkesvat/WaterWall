add_library(missing_abi_node_library SHARED ${WATERWALL_UNIT_SOURCE_ROOT}/core/legacy_node_library.c)
target_compile_definitions(missing_abi_node_library PRIVATE FIXTURE_NODE_TYPE="MissingAbiFixture")
set_target_properties(missing_abi_node_library PROPERTIES PREFIX "")
add_library(mismatched_abi_node_library SHARED ${WATERWALL_UNIT_SOURCE_ROOT}/core/legacy_node_library.c)
target_compile_definitions(mismatched_abi_node_library PRIVATE FIXTURE_NODE_TYPE="MismatchedAbiFixture")
set_target_properties(mismatched_abi_node_library PROPERTIES PREFIX "")
add_library(external_node_abi_v3_library SHARED ${WATERWALL_UNIT_SOURCE_ROOT}/core/lifecycle_v2_node_library.c)
set_target_properties(external_node_abi_v3_library PROPERTIES PREFIX "")
set(node_fixture_targets missing_abi_node_library mismatched_abi_node_library external_node_abi_v3_library)
if(WIN32)
  # Older DLLs return the layout revision without any atomic-backend tag.
  target_compile_definitions(mismatched_abi_node_library PRIVATE FIXTURE_ABI_VERSION=10)
  add_library(other_atomic_abi_node_library SHARED ${WATERWALL_UNIT_SOURCE_ROOT}/core/legacy_node_library.c)
  if(WW_HAVE_C11_ATOMICS)
    target_compile_definitions(other_atomic_abi_node_library PRIVATE
      WW_HAVE_C11_ATOMICS=0 FIXTURE_ABI_VERSION=WW_EXTERNAL_NODE_ABI_VERSION)
  else()
    # This compiler cannot compile the C11 layout. Model its exported descriptor only.
    target_compile_definitions(other_atomic_abi_node_library PRIVATE FIXTURE_C11_DESCRIPTOR_ONLY=1)
  endif()
  target_compile_definitions(other_atomic_abi_node_library PRIVATE FIXTURE_NODE_TYPE="OtherAtomicAbiFixture")
  set_target_properties(other_atomic_abi_node_library PROPERTIES PREFIX "")
  list(APPEND node_fixture_targets other_atomic_abi_node_library)
  foreach(fixture IN LISTS node_fixture_targets)
    # The DLL exports node entry points and consumes headers only.
    target_include_directories(${fixture} PRIVATE "$<TARGET_PROPERTY:ww,INCLUDE_DIRECTORIES>")
    target_compile_definitions(${fixture} PRIVATE "$<TARGET_PROPERTY:ww,COMPILE_DEFINITIONS>")
    if(MINGW)
      # The PE linker resolves unused static functions from public headers even with --gc-sections.
      # Omit those functions in the DLL while keeping Debug assertions and debug information.
      target_compile_options(${fixture} PRIVATE "$<$<CONFIG:Debug>:-Og>")
    elseif(MSVC)
      target_compile_options(${fixture} PRIVATE /Gy)
      target_link_options(${fixture} PRIVATE /OPT:REF /INCREMENTAL:NO)
    endif()
  endforeach()
else()
  target_compile_definitions(mismatched_abi_node_library PRIVATE FIXTURE_ABI_VERSION=9)
endif()
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND NOT MSVC)
  foreach(fixture IN LISTS node_fixture_targets)
    # Drop otherwise-unused public inline helpers that reference application-owned symbols.
    target_compile_options(${fixture} PRIVATE -ffunction-sections -fdata-sections)
    target_link_options(${fixture} PRIVATE "LINKER:--gc-sections")
  endforeach()
endif()
waterwall_add_native_executable(legacy_node_compatibility_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/core/legacy_node_compatibility_test.c)
target_link_libraries(legacy_node_compatibility_test PRIVATE ww)
set_target_properties(legacy_node_compatibility_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON)
if(MINGW)
  target_link_options(legacy_node_compatibility_test PRIVATE -static)
endif()
if(WIN32)
  # Locate DLLs beside the executable even when a Linux host runs it under Wine.
  set(fixture_path TARGET_FILE_NAME)
  target_compile_definitions(legacy_node_compatibility_test PRIVATE
    OTHER_ATOMIC_NODE_LIBRARY_PATH="$<TARGET_FILE_NAME:other_atomic_abi_node_library>")
else()
  set(fixture_path TARGET_FILE)
endif()
target_compile_definitions(legacy_node_compatibility_test PRIVATE
  MISSING_NODE_LIBRARY_PATH="$<${fixture_path}:missing_abi_node_library>"
  MISMATCHED_NODE_LIBRARY_PATH="$<${fixture_path}:mismatched_abi_node_library>"
  EXTERNAL_NODE_ABI_V3_LIBRARY_PATH="$<${fixture_path}:external_node_abi_v3_library>")
add_dependencies(legacy_node_compatibility_test ${node_fixture_targets})
if(WIN32)
  waterwall_register_native_test(waterwall.external_node_abi_v3_unit legacy_node_compatibility_test
    "unit;net;tunnels;node-manager;abi;portable" AGGREGATE waterwall_platform_unit_tests)
else()
  add_waterwall_unit_test(waterwall.external_node_abi_v3_unit legacy_node_compatibility_test
    "unit;net;tunnels;node-manager;abi;external-node-v3;portable")
endif()
