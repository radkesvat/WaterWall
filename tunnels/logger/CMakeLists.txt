

add_library(LoggerTunnel STATIC
      logger_tunnel.c
                 
)

# target_include_directories(LoggerTunnel PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

#ww api
target_include_directories(LoggerTunnel PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(LoggerTunnel ww)


# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)


target_compile_definitions(LoggerTunnel PRIVATE  LoggerTunnel_VERSION=0.1)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(LoggerTunnel PRIVATE  DEBUG=1)
endif()
