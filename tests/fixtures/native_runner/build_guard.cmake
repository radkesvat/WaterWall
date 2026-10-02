if(EXISTS "${ACTIVE_FILE}")
  message(FATAL_ERROR "A runner tried to build while the fixture executable was in use")
endif()
