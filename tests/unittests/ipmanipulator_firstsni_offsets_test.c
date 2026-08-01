#include "IpManipulator/structure.h"
#include "wlibc.h"

enum
{
    kIpv4HeaderLength              = 20,
    kTcpHeaderLength               = 20,
    kTlsRecordHeaderLength         = 5,
    kHandshakeHeaderLength         = 4,
    kClientHelloFixedLength        = 43,
    kExtensionsLengthFieldOffset   = 90,
    kSupportedVersionsExtensionLen = 7,
    kKeyShareExtensionLen          = 10
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static uint32_t appendExtension(uint8_t *dest, uint16_t type, const uint8_t *data, uint16_t data_len)
{
    PUT_BE16(dest, type);
    PUT_BE16(dest + 2, data_len);
    memoryCopy(dest + 4, data, data_len);
    return 4U + data_len;
}

static sbuf_t *buildClientHello(bool sni_first, const char *server_name)
{
    static const uint8_t supported_versions[] = {0x02, 0x03, 0x04};
    static const uint8_t key_share[]          = {0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD};

    uint16_t server_name_len = (uint16_t) stringLength(server_name);
    uint16_t sni_data_len    = (uint16_t) (5U + server_name_len);
    uint16_t extensions_len  = (uint16_t) (4U + sni_data_len);
    if (! sni_first)
    {
        extensions_len += kSupportedVersionsExtensionLen + kKeyShareExtensionLen;
    }

    uint32_t client_hello_len = kClientHelloFixedLength + extensions_len;
    uint16_t tls_record_len   = (uint16_t) (kHandshakeHeaderLength + client_hello_len);
    uint16_t packet_len = (uint16_t) (kIpv4HeaderLength + kTcpHeaderLength + kTlsRecordHeaderLength + tls_record_len);

    sbuf_t *buf = sbufCreate(packet_len);
    require(buf != NULL, "failed to allocate ClientHello buffer");
    sbufSetLength(buf, packet_len);

    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, packet_len);

    struct ip_hdr *ip = (struct ip_hdr *) packet;
    IPH_VHL_SET(ip, 4, kIpv4HeaderLength / 4);
    IPH_LEN_SET(ip, lwip_htons(packet_len));
    IPH_PROTO_SET(ip, IPPROTO_TCP);

    struct tcp_hdr *tcp = (struct tcp_hdr *) (packet + kIpv4HeaderLength);
    TCPH_HDRLEN_FLAGS_SET(tcp, kTcpHeaderLength / 4, TCP_ACK);

    uint8_t *tls = packet + kIpv4HeaderLength + kTcpHeaderLength;
    tls[0]       = 0x16;
    tls[1]       = 0x03;
    tls[2]       = 0x03;
    PUT_BE16(tls + 3, tls_record_len);
    tls[5] = 0x01;
    PUT_BE24(tls + 6, client_hello_len);

    uint8_t *client_hello = tls + 9;
    client_hello[0]       = 0x03;
    client_hello[1]       = 0x03;

    uint8_t *cursor = client_hello + 34;
    *cursor++       = 0;
    PUT_BE16(cursor, 2);
    cursor += 2;
    PUT_BE16(cursor, 0x1301);
    cursor += 2;
    *cursor++ = 1;
    *cursor++ = 0;
    PUT_BE16(cursor, extensions_len);
    cursor += 2;

    if (! sni_first)
    {
        cursor += appendExtension(cursor, 0x002B, supported_versions, sizeof(supported_versions));
        cursor += appendExtension(cursor, 0x0033, key_share, sizeof(key_share));
    }

    PUT_BE16(cursor, 0);
    PUT_BE16(cursor + 2, sni_data_len);
    PUT_BE16(cursor + 4, (uint16_t) (3U + server_name_len));
    cursor[6] = 0;
    PUT_BE16(cursor + 7, server_name_len);
    memoryCopy(cursor + 9, server_name, server_name_len);

    return buf;
}

static sbuf_t *rewriteSni(const sbuf_t *source, const sni_match_t *match, const char *replacement)
{
    uint16_t replacement_len = (uint16_t) stringLength(replacement);
    int32_t  delta           = (int32_t) replacement_len - (int32_t) match->sni_name_len;
    uint32_t source_len      = sbufGetLength(source);
    uint32_t rewritten_len   = (uint32_t) ((int32_t) source_len + delta);
    sbuf_t  *rewritten       = sbufCreate(rewritten_len);

    require(rewritten != NULL, "failed to allocate rewritten ClientHello");
    sbufSetLength(rewritten, rewritten_len);

    const uint8_t *src         = sbufGetRawPtr(source);
    uint8_t       *dest        = sbufGetMutablePtr(rewritten);
    uint32_t       tail_offset = match->sni_name_offset + match->sni_name_len;

    memoryCopyLarge(dest, src, match->sni_name_offset);
    memoryCopy(dest + match->sni_name_offset, replacement, replacement_len);
    memoryCopyLarge(dest + match->sni_name_offset + replacement_len, src + tail_offset, source_len - tail_offset);

    PUT_BE16(dest + match->sni_name_len_field_offset, replacement_len);
    PUT_BE16(dest + match->extensions_len_field_offset, (uint16_t) ((int32_t) match->extensions_len + delta));
    PUT_BE16(dest + match->server_name_list_len_field_offset,
             (uint16_t) ((int32_t) match->server_name_list_len + delta));
    PUT_BE16(dest + match->server_name_ext_len_field_offset, (uint16_t) ((int32_t) match->server_name_ext_len + delta));
    PUT_BE16(dest + match->tls_record_len_field_offset, (uint16_t) ((int32_t) match->tls_record_len + delta));
    PUT_BE24(dest + match->client_hello_len_field_offset, (uint32_t) ((int32_t) match->client_hello_len + delta));
    IPH_LEN_SET((struct ip_hdr *) dest, lwip_htons((uint16_t) ((int32_t) match->ip_total_len + delta)));

    return rewritten;
}

static void testSniFirstGoldenOffset(void)
{
    sbuf_t     *buf   = buildClientHello(true, "example.com");
    sni_match_t match = {0};

    require(parseClientHelloSni(sbufGetRawPtr(buf), sbufGetLength(buf), &match), "failed to parse first-extension SNI");
    require(match.extensions_len_field_offset == kExtensionsLengthFieldOffset,
            "first-extension SNI changed the golden extensions-length offset");

    sbufDestroy(buf);
}

static void testSniAfterOtherExtensions(void)
{
    sbuf_t     *buf   = buildClientHello(false, "example.com");
    sni_match_t match = {0};

    require(parseClientHelloSni(sbufGetRawPtr(buf), sbufGetLength(buf), &match), "failed to parse later SNI");
    require(match.extensions_len_field_offset == kExtensionsLengthFieldOffset,
            "later SNI did not point at the ClientHello extensions-length field");

    uint32_t sni_extension_offset =
        kExtensionsLengthFieldOffset + 2U + kSupportedVersionsExtensionLen + kKeyShareExtensionLen;
    uint32_t old_buggy_offset = sni_extension_offset - 2U;
    require(old_buggy_offset != match.extensions_len_field_offset, "test packet did not exercise the old bad offset");
    require(GET_BE16((const uint8_t *) sbufGetRawPtr(buf) + old_buggy_offset) == 0xCCDD,
            "old bad offset is not inside the preceding key_share extension data");

    sbufDestroy(buf);
}

static void testRewriteRoundTrip(void)
{
    sbuf_t     *buf   = buildClientHello(false, "a.test");
    sni_match_t match = {0};

    require(parseClientHelloSni(sbufGetRawPtr(buf), sbufGetLength(buf), &match), "failed to parse original SNI");

    sbuf_t     *rewritten = rewriteSni(buf, &match, "longer.example");
    sni_match_t reparsed  = {0};
    require(parseClientHelloSni(sbufGetRawPtr(rewritten), sbufGetLength(rewritten), &reparsed),
            "rewritten ClientHello did not re-parse");
    require(reparsed.extensions_len == match.extensions_len + stringLength("longer.example") - match.sni_name_len,
            "rewritten extensions length is inconsistent");
    require(reparsed.extensions_len_field_offset == kExtensionsLengthFieldOffset,
            "rewritten extensions-length offset drifted");

    sbufDestroy(rewritten);
    sbufDestroy(buf);
}

int main(void)
{
    testSniFirstGoldenOffset();
    testSniAfterOtherExtensions();
    testRewriteRoundTrip();
    return 0;
}
