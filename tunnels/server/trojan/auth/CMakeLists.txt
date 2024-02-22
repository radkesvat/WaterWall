

add_library(TrojanAuthServer STATIC
      trojan_auth_server.c
      ${CMAKE_CURRENT_SOURCE_DIR}/../../../../tunnels/shared/trojan/sha2.c         
)

# target_include_directories(TrojanAuthServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

#ww api
target_include_directories(TrojanAuthServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../ww)
target_include_directories(TrojanAuthServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../tunnels/)
target_link_libraries(TrojanAuthServer ww)
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
  target_include_directories(TrojanAuthServer PUBLIC ${stc_SOURCE_DIR}/include)
endif()



target_compile_options(TrojanAuthServer PRIVATE -ftrack-macro-expansion=0)
target_compile_definitions(TrojanAuthServer PRIVATE STC_STATIC=1 TrojanAuthServer_VERSION=0.1)

if(NOT CMAKE_BUILD_TYPE STREQUAL "RELASAE")
target_compile_definitions(TrojanAuthServer PRIVATE  DEBUG=1)

else()
target_compile_definitions(TrojanAuthServer PRIVATE  NDEBUG=1)

endif()