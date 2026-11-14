# Inspect the EnetCommon archive without executing anything. WaterWall adapters
# own every OS socket, so the ENet closure must not reference the socket API.
execute_process(
  COMMAND "${NM}" --undefined-only "${ENET_ARCHIVE}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE undefined_symbols
  ERROR_VARIABLE error
)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Cannot inspect ${ENET_ARCHIVE}: ${error}")
endif()

# ENet's callbacks.c always references abort. Its absence means nm could not
# read these objects (for example IPO bitcode), and the check would be empty.
if(NOT undefined_symbols MATCHES "(^|\n)[ \t]*U abort(@[^\n]*)?(\n|$)")
  message(FATAL_ERROR "${ENET_ARCHIVE} does not list ordinary undefined symbols; build it without IPO")
endif()

set(forbidden
  socket socketpair bind connect listen accept accept4
  recv recvfrom recvmsg recvmmsg send sendto sendmsg sendmmsg
  poll ppoll select pselect epoll_create epoll_create1 epoll_ctl epoll_wait
  getsockopt setsockopt getsockname getpeername shutdown)
foreach(name IN LISTS forbidden)
  if(undefined_symbols MATCHES "(^|\n)[ \t]*U ${name}(@[^\n]*)?(\n|$)")
    message(FATAL_ERROR "${ENET_ARCHIVE} references the OS socket function ${name}")
  endif()
endforeach()
message(STATUS "${ENET_ARCHIVE}: no OS socket references")
