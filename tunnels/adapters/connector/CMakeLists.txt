

add_library(Connector STATIC
                    connector.c
                 
)

# target_include_directories(Connector PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

#ww api
target_include_directories(Connector PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(Connector ww)
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
  target_include_directories(Connector PUBLIC ${stc_SOURCE_DIR}/include)
endif()



target_compile_options(Connector PRIVATE -ftrack-macro-expansion=0)
target_compile_definitions(Connector PRIVATE STC_STATIC=1 Connector_VERSION=0.1)

if(NOT CMAKE_BUILD_TYPE STREQUAL "RELASAE")
target_compile_definitions(Connector PRIVATE  DEBUG=1)

else()
target_compile_definitions(Connector PRIVATE  NDEBUG=1)

endif()
