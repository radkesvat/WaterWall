# download the generator https://github.com/nanopb/nanopb/tree/master/generator (0.4.8)
# and place the generator folder here next to grpc_client.c
# then execute "python3 generator/nanopb_generator.py packet.proto" to compile with protoc

add_library(GrpcClient STATIC
      grpc_client.c
      packet.pb.c
)


#ww api
target_include_directories(GrpcClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(GrpcClient PUBLIC ww)
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
  target_include_directories(GrpcClient PUBLIC ${stc_SOURCE_DIR}/include)
endif()


CPMAddPackage(
    NAME nanopb
    GIT_TAG 0.4.8
    GITHUB_REPOSITORY nanopb/nanopb
    DOWNLOAD_ONLY True

)
# list(APPEND CMAKE_MODULE_PATH ${nanopb_SOURCE_DIR}/extra)
# find_package(Nanopb REQUIRED)
# nanopb_generate_cpp(PROTO_SRCS PROTO_HDRS packet.proto)
# target_include_directories(GrpcClient PUBLIC ${nanopb_INCLUDE_DIRS})
# target_sources(GrpcClient PUBLIC ${PROTO_SRCS} ${PROTO_HDRS})

target_compile_options(GrpcClient PRIVATE -ftrack-macro-expansion=0)
target_compile_definitions(GrpcClient PRIVATE STC_STATIC=1 GrpcClient_VERSION=0.1)
target_include_directories(GrpcClient PUBLIC ${nanopb_SOURCE_DIR})
target_sources(GrpcClient PUBLIC  ${nanopb_SOURCE_DIR}/pb_decode.c
                        ${nanopb_SOURCE_DIR}/pb_common.c
                        ${nanopb_SOURCE_DIR}/pb_encode.c
                        
 )

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(GrpcClient PRIVATE  DEBUG=1)
endif()
