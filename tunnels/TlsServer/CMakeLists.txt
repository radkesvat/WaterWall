
add_library(TlsServer STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
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



target_include_directories(TlsServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(TlsServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/TlsServer)

include(CheckCSourceCompiles)
set(TLS_SERVER_OPENSSL_HEADER_AVAILABLE FALSE)
foreach(TLS_SERVER_OPENSSL_INCLUDE_DIR IN LISTS OPENSSL_INCLUDE_DIR OPENSSL_INCLUDE_DIRS)
  if(EXISTS "${TLS_SERVER_OPENSSL_INCLUDE_DIR}/openssl/ssl.h")
    set(TLS_SERVER_OPENSSL_HEADER_AVAILABLE TRUE)
  endif()
endforeach()

if(TLS_SERVER_OPENSSL_HEADER_AVAILABLE)
  if(DEFINED CMAKE_TRY_COMPILE_TARGET_TYPE)
    set(TLS_SERVER_SAVED_TRY_COMPILE_TARGET_TYPE "${CMAKE_TRY_COMPILE_TARGET_TYPE}")
    set(TLS_SERVER_HAD_TRY_COMPILE_TARGET_TYPE TRUE)
  endif()
  set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
  set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIRS})
  check_c_source_compiles(
    "#include <openssl/ssl.h>\nint main(void) { (void)&SSL_CTX_set_record_padding_callback; return 0; }"
    WW_OPENSSL_HAS_RECORD_PADDING_CALLBACK
  )
  unset(CMAKE_REQUIRED_INCLUDES)
  if(TLS_SERVER_HAD_TRY_COMPILE_TARGET_TYPE)
    set(CMAKE_TRY_COMPILE_TARGET_TYPE "${TLS_SERVER_SAVED_TRY_COMPILE_TARGET_TYPE}")
  else()
    unset(CMAKE_TRY_COMPILE_TARGET_TYPE)
  endif()
  unset(TLS_SERVER_HAD_TRY_COMPILE_TARGET_TYPE)
  unset(TLS_SERVER_SAVED_TRY_COMPILE_TARGET_TYPE)
elseif(DEFINED CPM_PACKAGE_openssl-source_SOURCE_DIR AND
       EXISTS "${CPM_PACKAGE_openssl-source_SOURCE_DIR}/include/openssl/ssl.h.in")
  file(STRINGS
    "${CPM_PACKAGE_openssl-source_SOURCE_DIR}/include/openssl/ssl.h.in"
    TLS_SERVER_OPENSSL_PADDING_DECLARATION
    REGEX "SSL_CTX_set_record_padding_callback"
    LIMIT_COUNT 1
  )
  if(TLS_SERVER_OPENSSL_PADDING_DECLARATION)
    set(WW_OPENSSL_HAS_RECORD_PADDING_CALLBACK TRUE CACHE INTERNAL "")
  endif()
else()
  message(FATAL_ERROR "TlsServer could not inspect the selected OpenSSL headers for SSL_CTX_set_record_padding_callback")
endif()
unset(TLS_SERVER_OPENSSL_HEADER_AVAILABLE)
unset(TLS_SERVER_OPENSSL_INCLUDE_DIR)
unset(TLS_SERVER_OPENSSL_PADDING_DECLARATION)
if(NOT WW_OPENSSL_HAS_RECORD_PADDING_CALLBACK)
  message(FATAL_ERROR "TlsServer tls13-record-shaping requires OpenSSL with SSL_CTX_set_record_padding_callback (OpenSSL 1.1.1 or newer)")
endif()

target_link_libraries(TlsServer ww TlsRecordShapingCommon)
if(NOT APPLE)
    target_precompile_headers(TlsServer REUSE_FROM ww)
endif()
