

add_library(TrojanSocksServer STATIC
      trojan_socks_server.c
)

# target_include_directories(TrojanSocksServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

#ww api
target_include_directories(TrojanSocksServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../ww)
target_include_directories(TrojanSocksServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../tunnels/)
target_link_libraries(TrojanSocksServer ww)
# target_compile_options(ww PUBLIC -fPIC)  

# add dependencies
include(../../../../cmake/CPM.cmake)


CPMAddPackage(
  NAME stc
  GIT_REPOSITORY https://github.com/stclib/STC
  GIT_TAG 09790f024ad29fca6fe60528461eeb589d4a917b
  DOWNLOAD_ONLY True
)


if(stc_ADDED)
  target_include_directories(TrojanSocksServer PUBLIC ${stc_SOURCE_DIR}/include)
endif()



target_compile_options(TrojanSocksServer PRIVATE -ftrack-macro-expansion=0)
target_compile_definitions(TrojanSocksServer PRIVATE STC_STATIC=1 TrojanSocksServer_VERSION=0.1)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(TrojanSocksServer PRIVATE  DEBUG=1)

endif()