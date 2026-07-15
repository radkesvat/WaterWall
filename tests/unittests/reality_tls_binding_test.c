#include "RealityServer/structure.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum
{
    kHandshakeClientHello = 0x01,
    kHandshakeServerHello = 0x02,
    kRecordHandshake      = 0x16,
    kRecordChangeCipherSpec = 0x14,
};

static const uint8_t kHelloRetryRequestRandom[32] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static size_t buildClientHelloBody(uint8_t *out)
{
    uint8_t *p = out;
    *p++ = 0x03;
    *p++ = 0x03;
    for (uint8_t i = 0; i < 32; ++i)
    {
        *p++ = i;
    }
    *p++ = 0;
    *p++ = 0;
    *p++ = 2;
    *p++ = 0x13;
    *p++ = 0x01;
    *p++ = 1;
    *p++ = 0;
    *p++ = 0;
    *p++ = 7;
    *p++ = 0;
    *p++ = 0x2b;
    *p++ = 0;
    *p++ = 3;
    *p++ = 2;
    *p++ = 0x03;
    *p++ = 0x04;
    return (size_t) (p - out);
}

static size_t buildServerHelloBody(uint8_t *out, const uint8_t random[32], bool tls13)
{
    uint8_t *p = out;
    *p++ = 0x03;
    *p++ = 0x03;
    memcpy(p, random, 32);
    p += 32;
    *p++ = 0;
    *p++ = 0x13;
    *p++ = 0x01;
    *p++ = 0;
    if (tls13)
    {
        *p++ = 0;
        *p++ = 6;
        *p++ = 0;
        *p++ = 0x2b;
        *p++ = 0;
        *p++ = 2;
        *p++ = 0x03;
        *p++ = 0x04;
    }
    return (size_t) (p - out);
}

static size_t buildHandshake(uint8_t type, const uint8_t *body, size_t body_len, uint8_t *out)
{
    out[0] = type;
    out[1] = (uint8_t) (body_len >> 16);
    out[2] = (uint8_t) (body_len >> 8);
    out[3] = (uint8_t) body_len;
    memcpy(out + 4, body, body_len);
    return body_len + 4;
}

static size_t buildRecord(uint8_t type, const uint8_t *body, size_t body_len, uint8_t *out)
{
    out[0] = type;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = (uint8_t) (body_len >> 8);
    out[4] = (uint8_t) body_len;
    memcpy(out + 5, body, body_len);
    return body_len + 5;
}

static void requireClientCapture(const realityserver_tls_capture_t *capture)
{
    require(capture->client_ready, "ClientHello capture not ready");
    require(capture->client_legacy_version == 0x0303, "ClientHello legacy version mismatch");
    for (uint8_t i = 0; i < 32; ++i)
    {
        require(capture->binding.client_random[i] == i, "ClientHello random mismatch");
    }
}

static void requireServerCapture(const realityserver_tls_capture_t *capture, uint16_t version)
{
    require(capture->server_ready, "ServerHello capture not ready");
    require(capture->binding.tls_version == version, "ServerHello selected version mismatch");
    require(capture->binding.cipher_suite == 0x1301, "ServerHello cipher mismatch");
    for (uint8_t i = 0; i < 32; ++i)
    {
        require(capture->binding.server_random[i] == (uint8_t) (0x80U + i), "ServerHello random mismatch");
    }
}

static void testClientHelloEveryCallbackSplit(void)
{
    uint8_t body[128];
    uint8_t handshake[160];
    uint8_t record[192];
    size_t body_len = buildClientHelloBody(body);
    size_t hs_len   = buildHandshake(kHandshakeClientHello, body, body_len, handshake);
    size_t record_len = buildRecord(kRecordHandshake, handshake, hs_len, record);

    for (size_t split = 0; split <= record_len; ++split)
    {
        realityserver_tls_parser_t parser;
        realityserver_tls_capture_t capture = {0};
        realityserverTlsParserInitialize(&parser, kRealityServerTlsParserClientHello);
        require(realityserverTlsParserFeed(&parser, record, split, &capture),
                "ClientHello first split feed failed");
        require(realityserverTlsParserFeed(&parser, record + split, record_len - split, &capture),
                "ClientHello second split feed failed");
        require(parser.complete, "ClientHello parser did not complete across callback split");
        requireClientCapture(&capture);
        realityserverTlsParserDestroy(&parser);
    }

    realityserver_tls_parser_t parser;
    realityserver_tls_capture_t capture = {0};
    realityserverTlsParserInitialize(&parser, kRealityServerTlsParserClientHello);
    for (size_t i = 0; i < record_len; ++i)
    {
        require(realityserverTlsParserFeed(&parser, record + i, 1, &capture),
                "one-byte ClientHello feed failed");
    }
    require(parser.complete, "one-byte ClientHello parser did not complete");
    requireClientCapture(&capture);
    realityserverTlsParserDestroy(&parser);
}

static void testClientHelloSpansRecords(void)
{
    uint8_t body[128];
    uint8_t handshake[160];
    uint8_t records[256];
    size_t body_len = buildClientHelloBody(body);
    size_t hs_len   = buildHandshake(kHandshakeClientHello, body, body_len, handshake);

    for (size_t split = 1; split < hs_len; ++split)
    {
        size_t first_len  = buildRecord(kRecordHandshake, handshake, split, records);
        size_t second_len = buildRecord(kRecordHandshake, handshake + split, hs_len - split, records + first_len);
        realityserver_tls_parser_t parser;
        realityserver_tls_capture_t capture = {0};
        realityserverTlsParserInitialize(&parser, kRealityServerTlsParserClientHello);
        require(realityserverTlsParserFeed(&parser, records, first_len + second_len, &capture),
                "record-fragmented ClientHello failed");
        require(parser.complete, "record-fragmented ClientHello did not complete");
        requireClientCapture(&capture);
        realityserverTlsParserDestroy(&parser);
    }
}

static void testServerHelloEveryCallbackSplit(void)
{
    uint8_t random[32];
    uint8_t body[128];
    uint8_t handshake[160];
    uint8_t record[192];
    for (uint8_t i = 0; i < 32; ++i)
    {
        random[i] = (uint8_t) (0x80U + i);
    }

    size_t body_len   = buildServerHelloBody(body, random, true);
    size_t hs_len     = buildHandshake(kHandshakeServerHello, body, body_len, handshake);
    size_t record_len = buildRecord(kRecordHandshake, handshake, hs_len, record);

    for (size_t split = 0; split <= record_len; ++split)
    {
        realityserver_tls_parser_t  parser;
        realityserver_tls_capture_t capture = {0};
        realityserverTlsParserInitialize(&parser, kRealityServerTlsParserServerHello);
        require(realityserverTlsParserFeed(&parser, record, split, &capture),
                "ServerHello first split feed failed");
        require(realityserverTlsParserFeed(&parser, record + split, record_len - split, &capture),
                "ServerHello second split feed failed");
        require(parser.complete, "ServerHello parser did not complete across callback split");
        requireServerCapture(&capture, 0x0304);
        realityserverTlsParserDestroy(&parser);
    }

    realityserver_tls_parser_t  parser;
    realityserver_tls_capture_t capture = {0};
    realityserverTlsParserInitialize(&parser, kRealityServerTlsParserServerHello);
    for (size_t i = 0; i < record_len; ++i)
    {
        require(realityserverTlsParserFeed(&parser, record + i, 1, &capture),
                "one-byte ServerHello feed failed");
    }
    require(parser.complete, "one-byte ServerHello parser did not complete");
    requireServerCapture(&capture, 0x0304);
    realityserverTlsParserDestroy(&parser);
}

static void testServerHelloSpansRecords(void)
{
    uint8_t random[32];
    uint8_t body[128];
    uint8_t handshake[160];
    uint8_t records[256];
    for (uint8_t i = 0; i < 32; ++i)
    {
        random[i] = (uint8_t) (0x80U + i);
    }

    size_t body_len = buildServerHelloBody(body, random, true);
    size_t hs_len   = buildHandshake(kHandshakeServerHello, body, body_len, handshake);

    for (size_t split = 1; split < hs_len; ++split)
    {
        size_t first_len  = buildRecord(kRecordHandshake, handshake, split, records);
        size_t second_len = buildRecord(kRecordHandshake, handshake + split, hs_len - split, records + first_len);
        realityserver_tls_parser_t  parser;
        realityserver_tls_capture_t capture = {0};
        realityserverTlsParserInitialize(&parser, kRealityServerTlsParserServerHello);
        require(realityserverTlsParserFeed(&parser, records, first_len + second_len, &capture),
                "record-fragmented ServerHello failed");
        require(parser.complete, "record-fragmented ServerHello did not complete");
        requireServerCapture(&capture, 0x0304);
        realityserverTlsParserDestroy(&parser);
    }
}

static void testTls13ServerHelloAndMultipleRecords(void)
{
    uint8_t random[32];
    uint8_t body[128];
    uint8_t handshake[160];
    uint8_t records[256];
    for (uint8_t i = 0; i < 32; ++i)
    {
        random[i] = (uint8_t) (0x80U + i);
    }
    size_t body_len = buildServerHelloBody(body, random, true);
    size_t hs_len   = buildHandshake(kHandshakeServerHello, body, body_len, handshake);
    const uint8_t ccs = 1;
    size_t record_len = buildRecord(kRecordChangeCipherSpec, &ccs, 1, records);
    record_len += buildRecord(kRecordHandshake, handshake, hs_len, records + record_len);

    realityserver_tls_parser_t parser;
    realityserver_tls_capture_t capture = {0};
    realityserverTlsParserInitialize(&parser, kRealityServerTlsParserServerHello);
    require(realityserverTlsParserFeed(&parser, records, record_len, &capture),
            "multiple-record ServerHello feed failed");
    require(parser.complete, "TLS 1.3 ServerHello parser did not complete");
    requireServerCapture(&capture, 0x0304);
    realityserverTlsParserDestroy(&parser);
}

static void testTls12ServerHello(void)
{
    uint8_t random[32];
    uint8_t body[128];
    uint8_t handshake[160];
    uint8_t record[192];
    for (uint8_t i = 0; i < 32; ++i)
    {
        random[i] = (uint8_t) (0x80U + i);
    }
    size_t body_len = buildServerHelloBody(body, random, false);
    size_t hs_len   = buildHandshake(kHandshakeServerHello, body, body_len, handshake);
    size_t record_len = buildRecord(kRecordHandshake, handshake, hs_len, record);

    realityserver_tls_parser_t parser;
    realityserver_tls_capture_t capture = {0};
    realityserverTlsParserInitialize(&parser, kRealityServerTlsParserServerHello);
    require(realityserverTlsParserFeed(&parser, record, record_len, &capture), "TLS 1.2 ServerHello feed failed");
    requireServerCapture(&capture, 0x0303);
    realityserverTlsParserDestroy(&parser);
}

static void testHelloRetryRequestWaitsForFinal(void)
{
    uint8_t final_random[32];
    uint8_t body[128];
    uint8_t handshake[160];
    uint8_t records[384];
    for (uint8_t i = 0; i < 32; ++i)
    {
        final_random[i] = (uint8_t) (0x80U + i);
    }

    size_t body_len = buildServerHelloBody(body, kHelloRetryRequestRandom, true);
    size_t hs_len   = buildHandshake(kHandshakeServerHello, body, body_len, handshake);
    size_t first_len = buildRecord(kRecordHandshake, handshake, hs_len, records);

    realityserver_tls_parser_t parser;
    realityserver_tls_capture_t capture = {0};
    realityserverTlsParserInitialize(&parser, kRealityServerTlsParserServerHello);
    require(realityserverTlsParserFeed(&parser, records, first_len, &capture), "HelloRetryRequest feed failed");
    require(! parser.complete && ! capture.server_ready, "HelloRetryRequest must not finalize binding");

    body_len = buildServerHelloBody(body, final_random, true);
    hs_len   = buildHandshake(kHandshakeServerHello, body, body_len, handshake);
    size_t second_len = buildRecord(kRecordHandshake, handshake, hs_len, records + first_len);
    require(realityserverTlsParserFeed(&parser, records + first_len, second_len, &capture),
            "final ServerHello after HRR failed");
    require(parser.complete, "final ServerHello after HRR did not complete");
    requireServerCapture(&capture, 0x0304);
    realityserverTlsParserDestroy(&parser);
}

static void testMalformedAndIncompleteInputs(void)
{
    uint8_t body[128];
    uint8_t handshake[160];
    uint8_t record[192];
    size_t body_len = buildClientHelloBody(body);
    body[41] = 0xff;
    body[42] = 0xff;
    size_t hs_len = buildHandshake(kHandshakeClientHello, body, body_len, handshake);
    size_t record_len = buildRecord(kRecordHandshake, handshake, hs_len, record);

    realityserver_tls_parser_t parser;
    realityserver_tls_capture_t capture = {0};
    realityserverTlsParserInitialize(&parser, kRealityServerTlsParserClientHello);
    require(! realityserverTlsParserFeed(&parser, record, record_len, &capture),
            "malformed nested ClientHello lengths must fail");
    require(parser.failed && ! capture.client_ready, "malformed ClientHello must not produce binding");
    realityserverTlsParserDestroy(&parser);

    const uint8_t oversized[] = {0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x01, 0x00, 0x00};
    capture = (realityserver_tls_capture_t) {0};
    realityserverTlsParserInitialize(&parser, kRealityServerTlsParserClientHello);
    require(! realityserverTlsParserFeed(&parser, oversized, sizeof(oversized), &capture),
            "oversized handshake length must fail");
    realityserverTlsParserDestroy(&parser);

    const uint8_t plaintext[] = "not tls";
    capture = (realityserver_tls_capture_t) {0};
    realityserverTlsParserInitialize(&parser, kRealityServerTlsParserClientHello);
    require(! realityserverTlsParserFeed(&parser, plaintext, sizeof(plaintext), &capture),
            "ordinary plaintext must fail TLS parsing");
    realityserverTlsParserDestroy(&parser);

    body_len = buildClientHelloBody(body);
    hs_len   = buildHandshake(kHandshakeClientHello, body, body_len, handshake);
    record_len = buildRecord(kRecordHandshake, handshake, hs_len, record);
    capture = (realityserver_tls_capture_t) {0};
    realityserverTlsParserInitialize(&parser, kRealityServerTlsParserClientHello);
    require(realityserverTlsParserFeed(&parser, record, record_len / 2, &capture),
            "incomplete ClientHello prefix should be retained");
    require(! parser.complete && ! capture.client_ready, "incomplete ClientHello must not produce binding");
    realityserverTlsParserDestroy(&parser);
}

int main(void)
{
    testClientHelloEveryCallbackSplit();
    testClientHelloSpansRecords();
    testServerHelloEveryCallbackSplit();
    testServerHelloSpansRecords();
    testTls13ServerHelloAndMultipleRecords();
    testTls12ServerHello();
    testHelloRetryRequestWaitsForFinal();
    testMalformedAndIncompleteInputs();
    return 0;
}
