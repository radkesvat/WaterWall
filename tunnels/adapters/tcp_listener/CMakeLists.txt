

add_library(TcpListener STATIC
                    tcp_listener.c
                 
)

# target_include_directories(TcpListener PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

#ww api
target_include_directories(TcpListener PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(TcpListener ww)
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
  target_include_directories(TcpListener PUBLIC ${stc_SOURCE_DIR}/include)
endif()



target_compile_definitions(TcpListener PRIVATE STC_STATIC=1 TcpListener_VERSION=0.1)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(TcpListener PRIVATE  DEBUG=1)

endif()
