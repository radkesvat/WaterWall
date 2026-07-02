add_library(Router STATIC
    common/classifier.c
    common/credentials.c
    common/geoip.c
    common/geosite_db.c
    common/line_state.c
    common/match_ip.c
    common/match_port.c
    common/rules.c
    common/sniffing.c
    common/stc_regex.c
    modules/matchers.c
    modules/source_ips/source_ips.c
    modules/source_port/source_port.c
    modules/network/network.c
    modules/password/password.c
    modules/protocol/protocol.c
    modules/attributes/attributes.c
    modules/destination_ip/destination_ip.c
    modules/destination_domain/destination_domain.c
    modules/username/username.c
    modules/destination_port/destination_port.c
    downstream/est.c
    downstream/fin.c
    downstream/init.c
    downstream/pause.c
    downstream/payload.c
    downstream/resume.c
    instance/api.c
    instance/chain.c
    instance/create.c
    instance/destroy.c
    instance/index.c
    instance/node.c
    instance/prepair.c
    instance/start.c
    instance/stop.c
    upstream/est.c
    upstream/fin.c
    upstream/init.c
    upstream/pause.c
    upstream/payload.c
    upstream/resume.c
)

target_include_directories(Router PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(Router PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(Router PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/Router)

target_link_libraries(Router PUBLIC ww DomainResolver)

if(router_enable_quic_sniffing)
    if(NOT TARGET OpenSSL::Crypto)
        message(FATAL_ERROR "Router QUIC sniffing is enabled, but OpenSSL::Crypto is not available")
    endif()

    add_library(RouterQuicSniffing OBJECT
        common/quic_sniffing.c
    )
    target_include_directories(RouterQuicSniffing PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_include_directories(RouterQuicSniffing PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_include_directories(RouterQuicSniffing PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/Router)
    target_link_libraries(RouterQuicSniffing PRIVATE ww OpenSSL::Crypto)

    target_compile_definitions(Router PUBLIC ROUTER_ENABLE_QUIC_SNIFFING=1)
    target_sources(Router PRIVATE $<TARGET_OBJECTS:RouterQuicSniffing>)
    target_link_libraries(Router PUBLIC OpenSSL::Crypto)
endif()

if(router_enable_http2_sniffing)
    if(NOT TARGET nghttp2_static)
        message(FATAL_ERROR "Router HTTP/2 sniffing is enabled, but nghttp2_static is not available")
    endif()

    add_library(RouterHttp2Sniffing OBJECT
        common/http2_sniffing.c
    )
    target_include_directories(RouterHttp2Sniffing PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_include_directories(RouterHttp2Sniffing PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_include_directories(RouterHttp2Sniffing PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/Router)
    target_link_libraries(RouterHttp2Sniffing PRIVATE ww nghttp2_static)

    target_compile_definitions(Router PUBLIC ROUTER_ENABLE_HTTP2_SNIFFING=1)
    target_sources(Router PRIVATE $<TARGET_OBJECTS:RouterHttp2Sniffing>)
    target_link_libraries(Router PUBLIC nghttp2_static)
endif()

if(TARGET maxminddb::maxminddb)
    get_target_property(ROUTER_MAXMIND_REAL_TARGET maxminddb::maxminddb ALIASED_TARGET)
    if(ROUTER_MAXMIND_REAL_TARGET)
        set_property(TARGET ${ROUTER_MAXMIND_REAL_TARGET} PROPERTY SYSTEM TRUE)
    else()
        set_property(TARGET maxminddb::maxminddb PROPERTY SYSTEM TRUE)
    endif()
    set(ROUTER_MAXMIND_TARGET maxminddb::maxminddb)
elseif(TARGET maxminddb)
    set_property(TARGET maxminddb PROPERTY SYSTEM TRUE)
    set(ROUTER_MAXMIND_TARGET maxminddb)
else()
    message(FATAL_ERROR "Router requires libmaxminddb, but no maxminddb CMake target was found")
endif()
target_link_libraries(Router PUBLIC ${ROUTER_MAXMIND_TARGET})

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set_source_files_properties(common/stc_regex.c PROPERTIES COMPILE_OPTIONS "-Wno-nested-externs")
endif()

if(NOT APPLE)
    target_precompile_headers(Router REUSE_FROM ww)
    if(TARGET RouterQuicSniffing)
        target_precompile_headers(RouterQuicSniffing REUSE_FROM ww)
    endif()
    if(TARGET RouterHttp2Sniffing)
        target_precompile_headers(RouterHttp2Sniffing REUSE_FROM ww)
    endif()
endif()
