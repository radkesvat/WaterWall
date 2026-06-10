#include "SniffRouter/structure.h"

#include <stdio.h>

static uint32_t make_client_hello(uint8_t *buf, const char *sni)
{
    uint8_t *cursor = buf;
    uint32_t sni_len = (uint32_t) stringLength(sni);

    *cursor++ = 0x16;
    *cursor++ = 0x03;
    *cursor++ = 0x01;
    uint8_t *record_len = cursor;
    cursor += 2;

    *cursor++ = 0x01;
    uint8_t *hello_len = cursor;
    cursor += 3;

    uint8_t *body = cursor;
    *cursor++ = 0x03;
    *cursor++ = 0x03;
    memorySet(cursor, 0x11, 32);
    cursor += 32;

    *cursor++ = 0;

    PUT_BE16(cursor, 2);
    cursor += 2;
    PUT_BE16(cursor, 0x1301);
    cursor += 2;

    *cursor++ = 1;
    *cursor++ = 0;

    uint8_t *extensions_len = cursor;
    cursor += 2;

    PUT_BE16(cursor, 0x0000);
    cursor += 2;
    PUT_BE16(cursor, (uint16_t) (2U + 3U + sni_len));
    cursor += 2;
    PUT_BE16(cursor, (uint16_t) (3U + sni_len));
    cursor += 2;
    *cursor++ = 0;
    PUT_BE16(cursor, (uint16_t) sni_len);
    cursor += 2;
    memoryCopy(cursor, sni, sni_len);
    cursor += sni_len;

    uint32_t ext_len = (uint32_t) (cursor - extensions_len - 2);
    uint32_t body_len = (uint32_t) (cursor - body);

    PUT_BE16(extensions_len, (uint16_t) ext_len);
    PUT_BE24(hello_len, body_len);
    PUT_BE16(record_len, (uint16_t) (4U + body_len));

    return (uint32_t) (cursor - buf);
}

static int expect_match(const char *name, sniffrouter_match_t got, enum sniffrouter_classify_result_e result,
                        tunnel_t *target)
{
    if (got.result == result && got.target == target)
    {
        return 0;
    }

    fprintf(stderr, "%s: got result=%d target=%p, expected result=%d target=%p\n",
            name,
            got.result,
            (void *) got.target,
            result,
            (void *) target);
    return 1;
}

int main(void)
{
    tunnel_t *http_target = (tunnel_t *) (uintptr_t) 0x10;
    tunnel_t *tls_target  = (tunnel_t *) (uintptr_t) 0x20;

    char http_domain[] = "api.example.test";
    char tls_domain[]  = "*.example.test";
    char *http_domains[] = {http_domain};
    char *tls_domains[]  = {tls_domain};

    sniffrouter_route_t routes[] = {
        {
            .tunnel        = http_target,
            .domains       = http_domains,
            .domains_count = 1,
            .detection     = kSniffDetectionHttp,
        },
        {
            .tunnel        = tls_target,
            .domains       = tls_domains,
            .domains_count = 1,
            .detection     = kSniffDetectionTlsClientHello,
        },
    };

    sniffrouter_tstate_t ts = {
        .routes       = routes,
        .routes_count = 2,
    };

    const uint8_t http_request[] = "GET / HTTP/1.1\r\nHost: api.example.test:443\r\n\r\n";
    if (expect_match("http route",
                     sniffrouterClassify(&ts, http_request, (uint32_t) sizeof(http_request) - 1U),
                     kSniffClassifyTarget,
                     http_target) != 0)
    {
        return 1;
    }

    uint8_t  hello[256];
    uint32_t hello_len = make_client_hello(hello, "www.example.test");
    if (expect_match("partial tls route",
                     sniffrouterClassify(&ts, hello, 3),
                     kSniffClassifyNeedMore,
                     NULL) != 0)
    {
        return 1;
    }

    if (expect_match("partial tls record body",
                     sniffrouterClassify(&ts, hello, 5),
                     kSniffClassifyNeedMore,
                     NULL) != 0)
    {
        return 1;
    }

    if (expect_match("tls route",
                     sniffrouterClassify(&ts, hello, hello_len),
                     kSniffClassifyTarget,
                     tls_target) != 0)
    {
        return 1;
    }

    uint8_t bad_version_hello[256];
    memoryCopy(bad_version_hello, hello, hello_len);
    bad_version_hello[2] = 0x04;
    if (expect_match("invalid tls record version",
                     sniffrouterClassify(&ts, bad_version_hello, hello_len),
                     kSniffClassifyDefault,
                     NULL) != 0)
    {
        return 1;
    }

    routes[1].detection = kSniffDetectionHttp;
    if (expect_match("tls disabled for route",
                     sniffrouterClassify(&ts, hello, hello_len),
                     kSniffClassifyDefault,
                     NULL) != 0)
    {
        return 1;
    }

    routes[1].detection = kSniffDetectionHttp | kSniffDetectionTlsClientHello;
    if (expect_match("combined detection route",
                     sniffrouterClassify(&ts, hello, hello_len),
                     kSniffClassifyTarget,
                     tls_target) != 0)
    {
        return 1;
    }

    // Reverse-link handshake detection.
    tunnel_t *reverse_target = (tunnel_t *) (uintptr_t) 0x30;

    char  reverse_http_domain[]  = "api.example.test";
    char *reverse_http_domains[] = {reverse_http_domain};

    sniffrouter_route_t reverse_routes[] = {
        {
            .tunnel        = http_target,
            .domains       = reverse_http_domains,
            .domains_count = 1,
            .detection     = kSniffDetectionHttp,
        },
        {
            .tunnel        = reverse_target,
            .domains       = NULL,
            .domains_count = 0,
            .detection     = kSniffDetectionReverse,
        },
    };

    sniffrouter_tstate_t reverse_ts = {
        .routes       = reverse_routes,
        .routes_count = 2,
    };

    uint8_t handshake[8192];
    if (reverseclientHandshakeLength == 0 || reverseclientHandshakeLength + 16U > sizeof(handshake))
    {
        fprintf(stderr, "reverse handshake test buffer is too small\n");
        return 1;
    }
    memoryCopy(handshake, reverseclientHandshakeBytes, reverseclientHandshakeLength);
    memorySet(handshake + reverseclientHandshakeLength, 0x55, 16U);

    if (expect_match("reverse handshake route",
                     sniffrouterClassify(&reverse_ts, handshake, reverseclientHandshakeLength),
                     kSniffClassifyTarget,
                     reverse_target) != 0)
    {
        return 1;
    }

    if (expect_match("reverse handshake with trailer",
                     sniffrouterClassify(&reverse_ts, handshake, reverseclientHandshakeLength + 16U),
                     kSniffClassifyTarget,
                     reverse_target) != 0)
    {
        return 1;
    }

    if (expect_match("reverse handshake partial falls back",
                     sniffrouterClassify(&reverse_ts, handshake, reverseclientHandshakeLength - 1U),
                     kSniffClassifyDefault,
                     NULL) != 0)
    {
        return 1;
    }

    uint8_t broken_handshake[8192];
    memoryCopy(broken_handshake, reverseclientHandshakeBytes, reverseclientHandshakeLength);
    broken_handshake[reverseclientHandshakeLength / 2U] ^= 0x01U;
    if (expect_match("reverse handshake interrupted falls back",
                     sniffrouterClassify(&reverse_ts, broken_handshake, reverseclientHandshakeLength),
                     kSniffClassifyDefault,
                     NULL) != 0)
    {
        return 1;
    }

    if (expect_match("http route beside reverse route",
                     sniffrouterClassify(&reverse_ts, http_request, (uint32_t) sizeof(http_request) - 1U),
                     kSniffClassifyTarget,
                     http_target) != 0)
    {
        return 1;
    }

    reverse_routes[1].detection     = kSniffDetectionHttp | kSniffDetectionReverse;
    reverse_routes[1].domains       = reverse_http_domains;
    reverse_routes[1].domains_count = 1;
    if (expect_match("combined http+reverse matches handshake",
                     sniffrouterClassify(&reverse_ts, handshake, reverseclientHandshakeLength),
                     kSniffClassifyTarget,
                     reverse_target) != 0)
    {
        return 1;
    }

    reverse_routes[1].detection = kSniffDetectionHttp;
    if (expect_match("reverse detection disabled falls back",
                     sniffrouterClassify(&reverse_ts, handshake, reverseclientHandshakeLength),
                     kSniffClassifyDefault,
                     NULL) != 0)
    {
        return 1;
    }

    uint8_t custom_handshake[32];
    const char custom_secret[] = "unit-secret";
    for (uint32_t i = 0; i < (uint32_t) sizeof(custom_handshake); ++i)
    {
        custom_handshake[i] = reverseclientHandshakeBytes[i % reverseclientHandshakeLength] ^
                              (uint8_t) custom_secret[i % ((uint32_t) sizeof(custom_secret) - 1U)];
    }

    reverse_routes[1].detection     = kSniffDetectionReverse;
    reverse_routes[1].domains       = NULL;
    reverse_routes[1].domains_count = 0;

    sniffrouter_tstate_t custom_reverse_ts = {
        .routes                   = reverse_routes,
        .routes_count             = 2,
        .reverse_handshake_bytes  = custom_handshake,
        .reverse_handshake_length = (uint32_t) sizeof(custom_handshake),
    };

    if (expect_match("custom reverse handshake route",
                     sniffrouterClassify(&custom_reverse_ts, custom_handshake, (uint32_t) sizeof(custom_handshake)),
                     kSniffClassifyTarget,
                     reverse_target) != 0)
    {
        return 1;
    }

    if (expect_match("default reverse handshake misses custom route",
                     sniffrouterClassify(&custom_reverse_ts, handshake, reverseclientHandshakeLength),
                     kSniffClassifyDefault,
                     NULL) != 0)
    {
        return 1;
    }

    if (expect_match("custom reverse partial falls back",
                     sniffrouterClassify(&custom_reverse_ts, custom_handshake,
                                         (uint32_t) sizeof(custom_handshake) - 1U),
                     kSniffClassifyDefault,
                     NULL) != 0)
    {
        return 1;
    }

    return 0;
}
