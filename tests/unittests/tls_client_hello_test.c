#include "tls_client_hello.h"

enum
{
    kHelloCapacity = 512,
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static uint32_t makeClientHello(uint8_t *record, const char *hostname, bool add_ech, bool add_psk)
{
    uint8_t *cursor        = record;
    *cursor++              = 0x16;
    *cursor++              = 0x03;
    *cursor++              = 0x03;
    uint8_t *record_length = cursor;
    cursor += 2U;

    *cursor++                 = 0x01;
    uint8_t *handshake_length = cursor;
    cursor += 3U;
    uint8_t *body = cursor;

    *cursor++ = 0x03;
    *cursor++ = 0x03;
    memorySet(cursor, 0xA5, 32);
    cursor += 32U;
    *cursor++ = 0;
    PUT_BE16(cursor, 2);
    cursor += 2U;
    PUT_BE16(cursor, 0x1301);
    cursor += 2U;
    *cursor++ = 1;
    *cursor++ = 0;

    uint8_t *extensions_length = cursor;
    cursor += 2U;

    if (add_ech)
    {
        PUT_BE16(cursor, 0xFE0D);
        cursor += 2U;
        PUT_BE16(cursor, 3);
        cursor += 2U;
        *cursor++ = 1;
        *cursor++ = 2;
        *cursor++ = 3;
    }

    if (hostname != NULL)
    {
        uint16_t hostname_length = (uint16_t) stringLength(hostname);
        PUT_BE16(cursor, 0x0000);
        cursor += 2U;
        PUT_BE16(cursor, (uint16_t) (2U + 3U + hostname_length));
        cursor += 2U;
        PUT_BE16(cursor, (uint16_t) (3U + hostname_length));
        cursor += 2U;
        *cursor++ = 0;
        PUT_BE16(cursor, hostname_length);
        cursor += 2U;
        memoryCopy(cursor, hostname, hostname_length);
        cursor += hostname_length;
    }

    if (add_psk)
    {
        PUT_BE16(cursor, 0x0029);
        cursor += 2U;
        PUT_BE16(cursor, 0);
        cursor += 2U;
    }

    uint32_t extensions_size = (uint32_t) (cursor - extensions_length - 2U);
    uint32_t body_size       = (uint32_t) (cursor - body);
    PUT_BE16(extensions_length, (uint16_t) extensions_size);
    PUT_BE24(handshake_length, body_size);
    PUT_BE16(record_length, (uint16_t) (body_size + 4U));
    return (uint32_t) (cursor - record);
}

int main(void)
{
    static const char hostname[] = "shared-parser.example";
    uint8_t           record[kHelloCapacity];
    uint32_t          record_length = makeClientHello(record, hostname, true, true);

    tls_client_hello_view_t view = {0};
    require(tlsclienthelloParseRecord(record, record_length, &view) == kTlsClientHelloFound,
            "valid ClientHello record was rejected");
    require(view.record_total_length == record_length && view.has_sni && view.has_ech && view.has_psk &&
                view.ech_before_sni,
            "ClientHello extension metadata is incomplete");
    require(view.sni_name_length == sizeof(hostname) - 1U &&
                memoryCompare(record + view.sni_name_offset, hostname, sizeof(hostname) - 1U) == 0,
            "ClientHello SNI offset is incorrect");
    require(GET_BE16(record + view.sni_extension_length_field_offset) == view.sni_extension_length &&
                GET_BE16(record + view.server_name_list_length_field_offset) == view.server_name_list_length,
            "ClientHello length-field offsets are incorrect");

    tls_client_hello_view_t handshake = {0};
    require(tlsclienthelloParseHandshake(record + 5U, record_length - 5U, &handshake) == kTlsClientHelloFound &&
                handshake.sni_name_offset + 5U == view.sni_name_offset,
            "raw handshake offsets disagree with record offsets");

    tls_client_hello_view_t body = {0};
    require(tlsclienthelloParseHandshakeBody(record + 9U, view.handshake_body_length, &body) == kTlsClientHelloFound &&
                body.sni_name_offset + 9U == view.sni_name_offset,
            "raw handshake-body offsets disagree with record offsets");

    for (uint32_t length = 0; length < record_length; ++length)
    {
        require(tlsclienthelloParseRecord(record, length, NULL) == kTlsClientHelloNeedMore,
                "partial ClientHello did not request more bytes");
    }

    uint8_t non_tls[] = {0x17, 0x03, 0x03, 0, 0};
    require(tlsclienthelloParseRecord(non_tls, sizeof(non_tls), NULL) == kTlsClientHelloNotClientHello,
            "non-handshake TLS record was misclassified");

    record_length = makeClientHello(record, NULL, false, false);
    require(tlsclienthelloParseRecord(record, record_length, &view) == kTlsClientHelloNoSni,
            "SNI-free ClientHello was not distinguished");

    record_length = makeClientHello(record, hostname, false, false);
    require(tlsclienthelloParseRecord(record, record_length, &view) == kTlsClientHelloFound,
            "valid malformed-test fixture was rejected");
    PUT_BE16(record + view.sni_name_length_field_offset, UINT16_MAX);
    require(tlsclienthelloParseRecord(record, record_length, NULL) == kTlsClientHelloMalformed,
            "malformed SNI length was accepted");
    return 0;
}
