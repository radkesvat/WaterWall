# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
foreach(tls_target IN ITEMS TlsClient TlsServer)
  if(TARGET ${tls_target})
    string(TOLOWER "${tls_target}" tls_name)
    set(bio_test "${tls_name}_buffer_bio_test")
    waterwall_add_native_executable(${bio_test} SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tls_buffer_bio_test.c)
    target_link_libraries(${bio_test} PRIVATE ${tls_target} ww)
    target_link_options(${bio_test} PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
    target_compile_definitions(${bio_test} PRIVATE
      TLS_BIO_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
      TLS_BIO_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key")
    if(tls_target STREQUAL "TlsClient")
      target_include_directories(${bio_test} BEFORE PRIVATE
        ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
        ${CMAKE_BINARY_DIR}/tunnels/TlsClient/boringssl/symbol_prefix_include)
      target_compile_definitions(${bio_test} PRIVATE BORINGSSL_PREFIX=WW_BSSL)
      target_link_libraries(${bio_test} PRIVATE ssl crypto)
      target_link_options(${bio_test} PRIVATE "-Wl,--wrap=WW_BSSL_EVP_AEAD_CTX_seal_scatter")
    endif()
    add_dependencies(waterwall_unit_tests ${bio_test})
    add_waterwall_unit_test(waterwall.${tls_name}_buffer_bio_unit ${bio_test}
      "unit;tunnels;${tls_name};buffers;ownership")
  endif()
endforeach()


# Linker --wrap only intercepts references that survive as real relocations. The production tunnel libraries are
# built with IPO in Release, where the compiler may inline a wrapped call before the linker ever sees it, so the
# tunnel under test is compiled straight into the (never-IPO) test executable instead of being linked as a
# library. This mirrors what the capture and device tests already do for the ww sources they inject faults into.
