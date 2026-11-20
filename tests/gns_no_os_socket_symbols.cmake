# Inspect the GameNetworkingSockets archive without executing anything.
# WaterWall adapters own every OS socket, so the closure that is built with the
# external transport must not reference the socket API, a poll call, or the
# descriptors upstream uses to wake its service thread.
execute_process(
  COMMAND "${NM}" --undefined-only "${GNS_ARCHIVE}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE undefined_symbols
  ERROR_VARIABLE error
)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Cannot inspect ${GNS_ARCHIVE}: ${error}")
endif()

# The library always copies memory. Its absence means nm could not read these
# objects (for example IPO bitcode), and the check would be empty.
if(NOT undefined_symbols MATCHES "(^|\n)[ \t]*U (memcpy|__memcpy_chk)(@[^\n]*)?(\n|$)")
  message(FATAL_ERROR "${GNS_ARCHIVE} does not list ordinary undefined symbols; build it without IPO")
endif()

set(forbidden
  socket socketpair bind connect listen accept accept4
  recv recvfrom recvmsg recvmmsg send sendto sendmsg sendmmsg
  poll ppoll select pselect epoll_create epoll_create1 epoll_ctl epoll_wait
  getsockopt setsockopt getsockname getpeername shutdown
  pipe pipe2 eventfd getaddrinfo getifaddrs)
foreach(name IN LISTS forbidden)
  if(undefined_symbols MATCHES "(^|\n)[ \t]*U ${name}(@[^\n]*)?(\n|$)")
    message(FATAL_ERROR "${GNS_ARCHIVE} references the OS function ${name}")
  endif()
endforeach()
message(STATUS "${GNS_ARCHIVE}: no OS socket references")
