

add_library(TcpConnector STATIC
                    resolve.c
                    tcp_connector.c
                 
)

# target_include_directories(TcpConnector PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

#ww api
target_include_directories(TcpConnector PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(TcpConnector ww)
# target_compile_options(ww PUBLIC -fPIC)  

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)


CPMAddPackage(
  NAME stc
  GIT_REPOSITORY https://github.com/stclib/STC
  GIT_TAG 09790f024ad29fca6fe60528461eeb589d4a917b
  DOWNLOAD_ONLY True
)


if(stc_ADDED)
  target_include_directories(TcpConnector PUBLIC ${stc_SOURCE_DIR}/include)
endif()



target_compile_options(TcpConnector PRIVATE -ftrack-macro-expansion=0)
target_compile_definitions(TcpConnector PRIVATE STC_STATIC=1 TcpConnector_VERSION=0.1)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(TcpConnector PRIVATE  DEBUG=1)

endif()
