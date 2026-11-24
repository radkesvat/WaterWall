foreach(dependency AuthenticationClient UserController PacketsToConnection)
  if(NOT TARGET ${dependency})
    message(FATAL_ERROR "WireGuardServer requires ${dependency}; enable its build option or disable INCLUDE_WIREGUARD_SERVER")
  endif()
endforeach()
add_library(WireGuardServer STATIC
  instance/node.c
  instance/create.c
  instance/chain.c
  instance/prepair.c
  instance/start.c
  instance/stop.c
  instance/destroy.c
  common/ingress.c
  common/bindings.c
  common/authorization.c
  common/user_binding.c
  common/output.c
  common/pending.c
  upstream/init.c
  upstream/fin.c
  upstream/payload.c
  upstream/pause.c
  upstream/resume.c
  downstream/fin.c
  downstream/payload.c
)
target_include_directories(WireGuardServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(WireGuardServer PUBLIC WireGuardCommon AuthenticationClient UserController PacketsToConnection)
if(NOT APPLE)
  target_precompile_headers(WireGuardServer REUSE_FROM ww)
endif()
