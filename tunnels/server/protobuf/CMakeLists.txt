# download the generator https://github.com/nanopb/nanopb/tree/master/generator (0.4.8)
# and place the generator folder here next to protobuf_server.c
# then execute "python3 generator/nanopb_generator.py packet.proto" to compile with protoc

add_library(ProtoBufServer STATIC
      protobuf_server.c
      ../../shared/packet.pb.c
)


#ww api
target_include_directories(ProtoBufServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(ProtoBufServer PUBLIC ww)
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
  target_include_directories(ProtoBufServer PUBLIC ${stc_SOURCE_DIR}/include)
endif()



CPMAddPackage(
    NAME nanopb
    GIT_TAG 0.4.8
    GITHUB_REPOSITORY nanopb/nanopb
    DOWNLOAD_ONLY True

)
target_link_libraries(ProtoBufServer PUBLIC)

# list(APPEND CMAKE_MODULE_PATH ${nanopb_SOURCE_DIR}/extra)
# find_package(Nanopb REQUIRED)
# nanopb_generate_cpp(PROTO_SRCS PROTO_HDRS packet.proto)
# target_include_directories(ProtoBufServer PUBLIC ${nanopb_INCLUDE_DIRS})
# target_sources(ProtoBufServer PUBLIC ${PROTO_SRCS} ${PROTO_HDRS})

target_compile_options(ProtoBufServer PRIVATE -ftrack-macro-expansion=0)
target_compile_definitions(ProtoBufServer PRIVATE STC_STATIC=1 ProtoBufServer_VERSION=0.1)
target_include_directories(ProtoBufServer PUBLIC ${nanopb_SOURCE_DIR})
target_sources(ProtoBufServer PUBLIC  ${nanopb_SOURCE_DIR}/pb_decode.c
                        ${nanopb_SOURCE_DIR}/pb_common.c
                        ${nanopb_SOURCE_DIR}/pb_encode.c
                        
 )

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(ProtoBufServer PRIVATE  DEBUG=1)
endif()
