# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
function(waterwall_line_failure_test_use_tunnel test_target tunnel_target)
  get_target_property(tunnel_dir "${tunnel_target}" SOURCE_DIR)
  get_target_property(tunnel_srcs "${tunnel_target}" SOURCES)
  get_target_property(tunnel_incs "${tunnel_target}" INCLUDE_DIRECTORIES)
  get_target_property(tunnel_interface_incs "${tunnel_target}" INTERFACE_INCLUDE_DIRECTORIES)
  get_target_property(tunnel_defs "${tunnel_target}" COMPILE_DEFINITIONS)
  get_target_property(tunnel_interface_defs "${tunnel_target}" INTERFACE_COMPILE_DEFINITIONS)
  get_target_property(tunnel_links "${tunnel_target}" LINK_LIBRARIES)
  get_target_property(tunnel_interface_links "${tunnel_target}" INTERFACE_LINK_LIBRARIES)

  set(resolved_sources "")
  foreach(source IN LISTS tunnel_srcs)
    if(IS_ABSOLUTE "${source}" OR source MATCHES "^\\$<")
      list(APPEND resolved_sources "${source}")
    else()
      list(APPEND resolved_sources "${tunnel_dir}/${source}")
    endif()
  endforeach()

  target_sources("${test_target}" PRIVATE ${resolved_sources})

  foreach(entry IN ITEMS tunnel_incs tunnel_interface_incs)
    if(${entry})
      target_include_directories("${test_target}" PRIVATE ${${entry}})
    endif()
  endforeach()

  foreach(entry IN ITEMS tunnel_defs tunnel_interface_defs)
    if(${entry})
      target_compile_definitions("${test_target}" PRIVATE ${${entry}})
    endif()
  endforeach()

  foreach(entry IN ITEMS tunnel_links tunnel_interface_links)
    if(${entry})
      target_link_libraries("${test_target}" PRIVATE ${${entry}})
    endif()
  endforeach()
endfunction()

# Focused packet-bridge coverage for user-visible classification, checksum,
# lifetime, and adapter-boundary contracts.
