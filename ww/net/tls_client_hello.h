#pragma once

/* Pure, transport-independent parsing of TLS ClientHello messages. */

#include "wlibc.h"

typedef enum tls_client_hello_result_e
{
    kTlsClientHelloNeedMore = 0,
    kTlsClientHelloNotClientHello,
    kTlsClientHelloMalformed,
    kTlsClientHelloNoSni,
    kTlsClientHelloFound,
} tls_client_hello_result_t;

typedef struct tls_client_hello_view_s
{
    uint32_t record_total_length;
    uint32_t record_body_length;
    uint32_t record_length_field_offset;

    uint32_t handshake_offset;
    uint32_t handshake_total_length;
    uint32_t handshake_body_offset;
    uint32_t handshake_body_length;
    uint32_t handshake_length_field_offset;

    uint32_t extensions_length_field_offset;
    uint32_t extensions_offset;
    uint16_t extensions_length;

    uint32_t sni_extension_offset;
    uint32_t sni_extension_length_field_offset;
    uint32_t server_name_list_length_field_offset;
    uint32_t sni_name_length_field_offset;
    uint32_t sni_name_offset;
    uint16_t sni_extension_length;
    uint16_t server_name_list_length;
    uint16_t sni_name_length;
    uint16_t sni_extension_index;

    uint32_t psk_extension_offset;
    uint16_t psk_extension_length;
    uint16_t psk_extension_index;

    uint32_t ech_extension_offset;
    uint32_t ech_extension_data_offset;
    uint16_t ech_extension_length;
    uint16_t ech_extension_index;

    bool has_sni;
    bool has_psk;
    bool has_ech;
    bool ech_before_sni;
} tls_client_hello_view_t;

/** Parse a ClientHello body without a four-byte TLS handshake header. */
tls_client_hello_result_t tlsclienthelloParseHandshakeBody(const uint8_t *body, size_t body_length,
                                                           tls_client_hello_view_t *view);

/** Parse one encoded TLS handshake message beginning with its type and length. */
tls_client_hello_result_t tlsclienthelloParseHandshake(const uint8_t *handshake, size_t available_length,
                                                       tls_client_hello_view_t *view);

/** Parse the first ClientHello in a complete or partial TLS handshake record. */
tls_client_hello_result_t tlsclienthelloParseRecord(const uint8_t *record, size_t available_length,
                                                    tls_client_hello_view_t *view);
