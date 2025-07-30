
add_library(TlsClient STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/chain.c
                    instance/index.c
                    common/helpers.c
                    common/line_state.c
                    upstream/init.c
                    upstream/est.c
                    upstream/fin.c
                    upstream/payload.c
                    upstream/pause.c
                    upstream/resume.c
                    upstream/est.c
                    downstream/init.c
                    downstream/est.c
                    downstream/fin.c
                    downstream/payload.c
                    downstream/pause.c
                    downstream/resume.c
                    downstream/est.c
  
)

target_include_directories(TlsClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)


target_link_libraries(TlsClient PRIVATE ww)

# set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)


# Configure BoringSSL options
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build BoringSSL as static library" FORCE)
set(INSTALL_ENABLED OFF CACHE BOOL "Disable BoringSSL installation" FORCE)
set(BUILD_TOOL OFF CACHE BOOL "Disable BoringSSL tools" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "Disable BoringSSL tests" FORCE)

########## NOTES
# The Downnloaded BoringSSL source code was the HEAD of the repository at the time of writing this.
# the commit hash is 4b3285002397da82681bebaacea9b4f231c9dbfc
# if i change anything inside it, the notes will be here:
# currently only removed git folder to be able to push it


# Add BoringSSL as a subdirectory
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/boringssl boringssl)

# Include BoringSSL headers
target_include_directories(TlsClient PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/boringssl/include
)



target_link_libraries(TlsClient PRIVATE crypto ssl)
