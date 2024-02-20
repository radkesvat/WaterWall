

add_library(tcp_listener STATIC
                    tcp_listener.c
                 
)

# target_include_directories(tcp_listener PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

#ww api
target_include_directories(tcp_listener PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(tcp_listener ww)
# target_compile_options(ww PUBLIC -fPIC)  

# add dependencies
include(../../../cmake/CPM.cmake)


CPMAddPackage(
  NAME stc
  GIT_REPOSITORY https://github.com/stclib/STC
  GIT_TAG 09790f024ad29fca6fe60528461eeb589d4a917b
  DOWNLOAD_ONLY True
)


if(stc_ADDED)
  target_include_directories(tcp_listener PUBLIC ${stc_SOURCE_DIR}/include)
endif()



target_compile_options(tcp_listener PRIVATE -ftrack-macro-expansion=0)
target_compile_definitions(tcp_listener PRIVATE STC_STATIC=1 tcp_listener_VERSION=0.1)

if(NODES_BUILD_RELEASE)
target_compile_definitions(tcp_listener PRIVATE NDEBUG=1)
else()
target_compile_definitions(tcp_listener PRIVATE DEBUG=1)
endif()
