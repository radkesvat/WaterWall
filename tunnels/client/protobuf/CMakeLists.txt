# download the generator https://github.com/nanopb/nanopb/tree/master/generator (0.4.8)
# and place the generator folder here next to protobuf_client.c
# then execute "python3 generator/nanopb_generator.py packet.proto" to compile with protoc

add_library(ProtoBufClient STATIC
      protobuf_client.c
      # ../../shared/protobuf/packet.pb.c

)


#ww api
target_include_directories(ProtoBufClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(ProtoBufClient PUBLIC ww)


target_include_directories(ProtoBufClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/protobuf)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

# CPMAddPackage(
#     NAME nanopb
#     GIT_TAG 0.4.8
#     GITHUB_REPOSITORY nanopb/nanopb
#     DOWNLOAD_ONLY True

# )
# target_link_libraries(ProtoBufClient PUBLIC)

# list(APPEND CMAKE_MODULE_PATH ${nanopb_SOURCE_DIR}/extra)
# find_package(Nanopb REQUIRED)
# nanopb_generate_cpp(PROTO_SRCS PROTO_HDRS packet.proto)
# target_include_directories(ProtoBufClient PUBLIC ${nanopb_INCLUDE_DIRS})
# target_sources(ProtoBufClient PUBLIC ${PROTO_SRCS} ${PROTO_HDRS})

target_compile_definitions(ProtoBufClient PRIVATE  ProtoBufClient_VERSION=0.1)
# target_include_directories(ProtoBufClient PUBLIC ${nanopb_SOURCE_DIR})
# target_sources(ProtoBufClient PUBLIC  ${nanopb_SOURCE_DIR}/pb_decode.c
#                         ${nanopb_SOURCE_DIR}/pb_common.c
#                         ${nanopb_SOURCE_DIR}/pb_encode.c
                        
#  )

