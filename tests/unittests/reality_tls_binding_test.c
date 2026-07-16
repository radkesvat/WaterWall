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
    kHandshakeCertificate = 0x0b,
    kHandshakeServerHelloDone = 0x0e,
    kHandshakeClientKeyExchange = 0x10,
    kHandshakeFinished = 0x14,
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

static size_t buildProtectedGcmRecord(uint64_t explicit_nonce, uint8_t *out);
static void   initializeGcmTracker(realityserver_tls12_record_tracker_t *tracker);

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

static size_t buildPlainHandshakeRecord(uint8_t type, uint8_t *out)
{
    const uint8_t body = 0xa5;
    uint8_t       handshake[5];
    size_t handshake_len = buildHandshake(type, &body, sizeof(body), handshake);
    return buildRecord(kRecordHandshake, handshake, handshake_len, out);
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

static void testFailedParsingAndTrackingPreserveBinding(void)
{
    realityserver_tls_capture_t capture = {
        .binding = {
            .tls_version  = kRealityV2Tls12,
            .cipher_suite = 0xC02F,
        },
        .client_legacy_version = kRealityV2Tls12,
        .client_ready          = true,
        .server_ready          = true,
    };
    for (uint8_t i = 0; i < kRealityV2TlsRandomSize; ++i)
    {
        capture.binding.client_random[i] = (uint8_t) (0x20U + i);
        capture.binding.server_random[i] = (uint8_t) (0x60U + i);
    }
    realityserver_tls_capture_t expected = capture;

    uint8_t body[128];
    uint8_t handshake[160];
    uint8_t record[192];
    size_t body_len = buildClientHelloBody(body);
    body[0]         = 0x02;
    size_t handshake_len = buildHandshake(kHandshakeClientHello, body, body_len, handshake);
    size_t record_len    = buildRecord(kRecordHandshake, handshake, handshake_len, record);

    realityserver_tls_parser_t parser;
    realityserverTlsParserInitialize(&parser, kRealityServerTlsParserClientHello);
    require(! realityserverTlsParserFeed(&parser, record, record_len, &capture) && parser.failed,
            "invalid ClientHello version must fail parsing");
    require(memoryEqual(&capture, &expected, sizeof(capture)),
            "failed parser must not overwrite a valid handshake binding");
    realityserverTlsParserDestroy(&parser);

    realityserver_lstate_t ls = {0};
    ls.tls_capture             = expected;
    initializeGcmTracker(&ls.client_record_tracker);
    const uint8_t ccs = 1;
    record_len = buildRecord(kRecordChangeCipherSpec, &ccs, sizeof(ccs), record);
    require(realityserverTls12RecordTrackerFeed(&ls.client_record_tracker, record, record_len),
            "binding-preservation tracker CCS failed");
    uint8_t malformed_body[23] = {0};
    record_len = buildRecord(kRecordHandshake, malformed_body, sizeof(malformed_body), record);
    require(! realityserverTls12RecordTrackerFeed(&ls.client_record_tracker, record, record_len) &&
                ls.client_record_tracker.failed,
            "malformed protected record must fail tracking");
    require(memoryEqual(&ls.tls_capture, &expected, sizeof(expected)),
            "failed tracker must not overwrite a valid handshake binding");
    realityserverTls12RecordTrackerDestroy(&ls.client_record_tracker);
}

static size_t buildProtectedGcmRecord(uint64_t explicit_nonce, uint8_t *out)
{
    uint8_t body[24] = {0};
    realityV2WriteBe64(body, explicit_nonce);
    memset(body + 8, 0xa5, sizeof(body) - 8);
    return buildRecord(0x16, body, sizeof(body), out);
}

static void initializeGcmTracker(realityserver_tls12_record_tracker_t *tracker)
{
    reality_v2_record_profile_t profile;
    require(realityV2SelectRecordProfile(kRealityV2Tls12, 0xC02F, &profile),
            "failed to select tracker GCM profile");
    realityserverTls12RecordTrackerInitialize(tracker);
    require(realityserverTls12RecordTrackerSetProfile(tracker, &profile),
            "failed to configure tracker GCM profile");
}

static void feedPlainHandshake(realityserver_tls12_record_tracker_t *tracker, uint8_t handshake_type,
                               const char *message)
{
    uint8_t record[32];
    size_t  record_len = buildPlainHandshakeRecord(handshake_type, record);
    require(realityserverTls12RecordTrackerFeed(tracker, record, record_len), message);
}

static void feedChangeCipherSpec(realityserver_tls12_record_tracker_t *tracker, const char *message)
{
    const uint8_t ccs = 1;
    uint8_t       record[16];
    size_t        record_len = buildRecord(kRecordChangeCipherSpec, &ccs, sizeof(ccs), record);
    require(realityserverTls12RecordTrackerFeed(tracker, record, record_len), message);
}

static void feedProtectedRecord(realityserver_tls12_record_tracker_t *tracker, uint64_t nonce,
                                const char *message)
{
    uint8_t record[64];
    size_t  record_len = buildProtectedGcmRecord(nonce, record);
    require(realityserverTls12RecordTrackerFeed(tracker, record, record_len), message);
}

static void testTls12PairedEpochActivationAndFullHandshakeOrdering(void)
{
    realityserver_tls12_record_tracker_t client;
    realityserver_tls12_record_tracker_t server;
    initializeGcmTracker(&client);
    initializeGcmTracker(&server);

    feedPlainHandshake(&client, kHandshakeClientHello, "full handshake ClientHello tracking failed");
    feedPlainHandshake(&server, kHandshakeServerHello, "full handshake ServerHello tracking failed");
    feedPlainHandshake(&server, kHandshakeCertificate, "full handshake Certificate tracking failed");
    feedPlainHandshake(&server, kHandshakeServerHelloDone, "full handshake ServerHelloDone tracking failed");
    feedPlainHandshake(&client, kHandshakeClientKeyExchange, "full handshake ClientKeyExchange tracking failed");
    require(! client.protected_epoch && ! server.protected_epoch,
            "full handshake plaintext flights must not activate either epoch");

    feedChangeCipherSpec(&client, "full handshake client CCS tracking failed");
    require(client.protected_epoch && ! server.protected_epoch,
            "client CCS must activate only the client protected epoch");
    feedProtectedRecord(&client, 0, "full handshake client Finished tracking failed");
    require(client.saw_protected_record && client.next_sequence == 1 &&
                ! server.saw_protected_record && server.next_sequence == 0,
            "client Finished must advance only the client sequence");

    feedChangeCipherSpec(&server, "full handshake server CCS tracking failed");
    require(client.protected_epoch && server.protected_epoch,
            "server CCS must independently activate the server protected epoch");
    feedProtectedRecord(&server, 0, "full handshake server Finished tracking failed");
    require(client.next_sequence == 1 && server.next_sequence == 1,
            "full handshake Finished ordering produced the wrong paired sequences");

    realityserverTls12RecordTrackerDestroy(&client);
    realityserverTls12RecordTrackerDestroy(&server);
}

static void testTls12ResumedHandshakeOrdering(void)
{
    realityserver_tls12_record_tracker_t client;
    realityserver_tls12_record_tracker_t server;
    initializeGcmTracker(&client);
    initializeGcmTracker(&server);

    feedPlainHandshake(&client, kHandshakeClientHello, "resumed handshake ClientHello tracking failed");
    feedPlainHandshake(&server, kHandshakeServerHello, "resumed handshake ServerHello tracking failed");
    feedChangeCipherSpec(&server, "resumed handshake server CCS tracking failed");
    feedProtectedRecord(&server, 0, "resumed handshake server Finished tracking failed");
    require(server.protected_epoch && server.next_sequence == 1 &&
                ! client.protected_epoch && client.next_sequence == 0,
            "resumed server flight must activate and advance only the server epoch");

    feedChangeCipherSpec(&client, "resumed handshake client CCS tracking failed");
    feedProtectedRecord(&client, 0, "resumed handshake client Finished tracking failed");
    require(client.protected_epoch && server.protected_epoch &&
                client.next_sequence == 1 && server.next_sequence == 1,
            "resumed handshake Finished ordering produced the wrong paired sequences");

    realityserverTls12RecordTrackerDestroy(&client);
    realityserverTls12RecordTrackerDestroy(&server);
}

static void initializeAuthorizationState(realityserver_lstate_t *ls)
{
    *ls = (realityserver_lstate_t) {0};
    ls->tls_capture.binding.tls_version  = kRealityV2Tls12;
    ls->tls_capture.binding.cipher_suite = 0xC02F;
    require(realityV2SelectRecordProfile(kRealityV2Tls12, 0xC02F, &ls->record_profile),
            "authorization test profile selection failed");
    initializeGcmTracker(&ls->client_record_tracker);
    initializeGcmTracker(&ls->server_record_tracker);
}

static void destroyAuthorizationState(realityserver_lstate_t *ls)
{
    realityserverTls12RecordTrackerDestroy(&ls->client_record_tracker);
    realityserverTls12RecordTrackerDestroy(&ls->server_record_tracker);
}

static void testTls12MissingFinishedRejectsAuthorization(void)
{
    realityserver_tstate_t ts = {
        .tls12_gcm_server_nonce_policy = kRealityServerGcmNoncePolicyAuto,
    };
    realityserver_lstate_t ls;

    initializeAuthorizationState(&ls);
    feedChangeCipherSpec(&ls.client_record_tracker, "missing-client-Finished CCS tracking failed");
    feedProtectedRecord(&ls.client_record_tracker, 0, "missing-client-Finished candidate tracking failed");
    feedChangeCipherSpec(&ls.server_record_tracker, "missing-client-Finished server CCS tracking failed");
    feedProtectedRecord(&ls.server_record_tracker, 0, "missing-client-Finished server Finished tracking failed");
    ls.c2s_recv_seq = 1;
    require(! realityserverFreezeTlsCamouflage(&ts, &ls),
            "authorization gate must reject a client takeover record without a preceding protected Finished");
    require(! ls.client_record_tracker.frozen && ! ls.server_record_tracker.frozen,
            "rejected authorization must not freeze incomplete trackers");
    destroyAuthorizationState(&ls);

    initializeAuthorizationState(&ls);
    feedChangeCipherSpec(&ls.client_record_tracker, "missing-server-Finished client CCS tracking failed");
    feedProtectedRecord(&ls.client_record_tracker, 0, "missing-server-Finished client Finished tracking failed");
    feedProtectedRecord(&ls.client_record_tracker, 1, "missing-server-Finished candidate tracking failed");
    feedChangeCipherSpec(&ls.server_record_tracker, "missing-server-Finished server CCS tracking failed");
    ls.c2s_recv_seq = 1;
    require(! realityserverFreezeTlsCamouflage(&ts, &ls),
            "authorization gate must reject takeover without a protected server Finished");
    require(! ls.client_record_tracker.frozen && ! ls.server_record_tracker.frozen,
            "missing server Finished must leave trackers unfrozen");
    destroyAuthorizationState(&ls);

    initializeAuthorizationState(&ls);
    feedChangeCipherSpec(&ls.client_record_tracker, "complete authorization client CCS tracking failed");
    feedProtectedRecord(&ls.client_record_tracker, 0, "complete authorization client Finished tracking failed");
    feedProtectedRecord(&ls.client_record_tracker, 1, "complete authorization candidate tracking failed");
    feedChangeCipherSpec(&ls.server_record_tracker, "complete authorization server CCS tracking failed");
    feedProtectedRecord(&ls.server_record_tracker, 0, "complete authorization server Finished tracking failed");
    ls.c2s_recv_seq = 1;
    require(realityserverFreezeTlsCamouflage(&ts, &ls),
            "authorization gate rejected complete TLS 1.2 Finished ordering");
    require(ls.client_record_tracker.frozen && ls.server_record_tracker.frozen &&
                ls.client_tls_sequence_base == 1 && ls.server_tls_sequence_base == 1,
            "successful authorization must freeze the expected directional sequence bases");
    destroyAuthorizationState(&ls);
}

static void testTls12RecordTrackerEveryCallbackSplit(void)
{
    uint8_t stream[128];
    const uint8_t ccs = 1;
    size_t stream_len = buildRecord(kRecordChangeCipherSpec, &ccs, 1, stream);
    stream_len += buildProtectedGcmRecord(0, stream + stream_len);
    stream_len += buildProtectedGcmRecord(1, stream + stream_len);

    for (size_t split = 0; split <= stream_len; ++split)
    {
        realityserver_tls12_record_tracker_t tracker;
        initializeGcmTracker(&tracker);
        require(realityserverTls12RecordTrackerFeed(&tracker, stream, split),
                "TLS 1.2 tracker first callback split failed");
        require(realityserverTls12RecordTrackerFeed(&tracker, stream + split, stream_len - split),
                "TLS 1.2 tracker second callback split failed");
        require(tracker.protected_epoch && tracker.saw_protected_record && tracker.next_sequence == 2,
                "TLS 1.2 tracker sequence state mismatch");
        require(tracker.explicit_nonce_sample_count == 2 && tracker.sequence_pattern && tracker.counter_pattern,
                "TLS 1.2 sequence-pattern samples mismatch");
        realityserverTls12RecordTrackerDestroy(&tracker);
    }

    realityserver_tls12_record_tracker_t tracker;
    initializeGcmTracker(&tracker);
    for (size_t i = 0; i < stream_len; ++i)
    {
        require(realityserverTls12RecordTrackerFeed(&tracker, stream + i, 1),
                "one-byte TLS 1.2 tracker feed failed");
    }
    require(tracker.next_sequence == 2 && tracker.last_record_sequence == 1,
            "one-byte TLS 1.2 tracker sequence mismatch");
    uint8_t policy = 0;
    uint64_t counter_next = 0;
    require(realityserverResolveGcmNoncePolicy(kRealityServerGcmNoncePolicyAuto,
                                               &tracker,
                                               &policy,
                                               &counter_next) &&
                policy == kRealityServerGcmNoncePolicySequence,
            "auto sequence policy resolution mismatch");
    realityserverTls12RecordTrackerDestroy(&tracker);
}

static void testTls12RecordTrackerPatternsAndProfiles(void)
{
    uint8_t records[128];
    const uint8_t ccs = 1;
    size_t len = buildRecord(kRecordChangeCipherSpec, &ccs, 1, records);
    len += buildProtectedGcmRecord(100, records + len);
    len += buildProtectedGcmRecord(101, records + len);

    realityserver_tls12_record_tracker_t tracker;
    initializeGcmTracker(&tracker);
    require(realityserverTls12RecordTrackerFeed(&tracker, records, len), "counter-pattern tracker feed failed");
    require(! tracker.sequence_pattern && tracker.counter_pattern && tracker.last_explicit_nonce == 101,
            "counter-pattern inference mismatch");
    uint8_t  policy = 0;
    uint64_t counter_next = 0;
    require(realityserverResolveGcmNoncePolicy(kRealityServerGcmNoncePolicyAuto,
                                               &tracker,
                                               &policy,
                                               &counter_next) &&
                policy == kRealityServerGcmNoncePolicyCounter && counter_next == 102,
            "auto counter policy resolution mismatch");
    require(realityserverResolveGcmNoncePolicy(kRealityServerGcmNoncePolicySequence,
                                               &tracker,
                                               &policy,
                                               &counter_next) &&
                policy == kRealityServerGcmNoncePolicySequence,
            "explicit sequence policy resolution mismatch");
    require(realityserverResolveGcmNoncePolicy(kRealityServerGcmNoncePolicyRandom,
                                               &tracker,
                                               &policy,
                                               &counter_next) &&
                policy == kRealityServerGcmNoncePolicyRandom,
            "explicit random policy resolution mismatch");
    realityserverTls12RecordTrackerFreeze(&tracker);
    uint64_t frozen_next = tracker.next_sequence;
    require(realityserverTls12RecordTrackerFeed(&tracker, records, len) && tracker.next_sequence == frozen_next,
            "frozen tracker must ignore takeover records");
    realityserverTls12RecordTrackerDestroy(&tracker);

    len = buildRecord(kRecordChangeCipherSpec, &ccs, 1, records);
    len += buildProtectedGcmRecord(9, records + len);
    len += buildProtectedGcmRecord(17, records + len);
    initializeGcmTracker(&tracker);
    require(realityserverTls12RecordTrackerFeed(&tracker, records, len), "random-pattern tracker feed failed");
    require(! tracker.sequence_pattern && ! tracker.counter_pattern, "random-pattern inference mismatch");
    require(realityserverResolveGcmNoncePolicy(kRealityServerGcmNoncePolicyAuto,
                                               &tracker,
                                               &policy,
                                               &counter_next) &&
                policy == kRealityServerGcmNoncePolicyRandom,
            "auto random policy resolution mismatch");
    realityserverTls12RecordTrackerDestroy(&tracker);

    reality_v2_record_profile_t cbc_profile;
    require(realityV2SelectRecordProfile(kRealityV2Tls12, 0xC013, &cbc_profile),
            "failed to select tracker CBC profile");
    realityserverTls12RecordTrackerInitialize(&tracker);
    require(realityserverTls12RecordTrackerSetProfile(&tracker, &cbc_profile),
            "failed to configure tracker CBC profile");
    uint8_t cbc_body[48];
    memset(cbc_body, 0x5c, sizeof(cbc_body));
    len = buildRecord(kRecordChangeCipherSpec, &ccs, 1, records);
    len += buildRecord(0x16, cbc_body, sizeof(cbc_body), records + len);
    require(realityserverTls12RecordTrackerFeed(&tracker, records, len), "CBC protected tracker feed failed");
    require(tracker.saw_protected_record && tracker.next_sequence == 1,
            "CBC protected tracker sequence mismatch");
    realityserverTls12RecordTrackerDestroy(&tracker);

    reality_v2_record_profile_t chacha_profile;
    require(realityV2SelectRecordProfile(kRealityV2Tls12, 0xCCA8, &chacha_profile) &&
                chacha_profile.profile_id == kRealityV2RecordProfileTls12ChaCha &&
                chacha_profile.visible_prefix_len == 0,
            "failed to select zero-prefix TLS 1.2 ChaCha tracker profile");
    realityserverTls12RecordTrackerInitialize(&tracker);
    require(realityserverTls12RecordTrackerSetProfile(&tracker, &chacha_profile),
            "failed to configure tracker TLS 1.2 ChaCha profile");
    uint8_t chacha_body[kRealityV2TagSize] = {0};
    len = buildRecord(kRecordChangeCipherSpec, &ccs, 1, records);
    len += buildRecord(0x17, chacha_body, sizeof(chacha_body), records + len);
    require(realityserverTls12RecordTrackerFeed(&tracker, records, len) &&
                tracker.saw_protected_record && tracker.next_sequence == 1,
            "TLS 1.2 ChaCha protected tracker feed failed");
    realityserverTls12RecordTrackerDestroy(&tracker);

    reality_v2_record_profile_t tls13_profile;
    require(realityV2SelectRecordProfile(kRealityV2Tls13, 0x1301, &tls13_profile),
            "failed to select TLS 1.3 profile for tracker rejection");
    realityserverTls12RecordTrackerInitialize(&tracker);
    require(! realityserverTls12RecordTrackerSetProfile(&tracker, &tls13_profile),
            "TLS 1.2 tracker must reject the TLS 1.3 AEAD profile");
    realityserverTls12RecordTrackerDestroy(&tracker);
}

static void testTls12RecordTrackerFailures(void)
{
    uint8_t records[64];
    const uint8_t ccs = 1;
    size_t ccs_len = buildRecord(kRecordChangeCipherSpec, &ccs, 1, records);

    realityserver_tls12_record_tracker_t tracker;
    initializeGcmTracker(&tracker);
    require(realityserverTls12RecordTrackerFeed(&tracker, records, ccs_len), "tracker CCS feed failed");
    require(tracker.protected_epoch && ! tracker.saw_protected_record,
            "CCS must activate an empty protected epoch");
    uint8_t short_body[23] = {0};
    size_t short_len = buildRecord(0x16, short_body, sizeof(short_body), records);
    require(! realityserverTls12RecordTrackerFeed(&tracker, records, short_len) && tracker.failed,
            "short protected GCM record must fail");
    realityserverTls12RecordTrackerDestroy(&tracker);

    initializeGcmTracker(&tracker);
    uint8_t policy = 0;
    uint64_t counter_next = 0;
    require(! realityserverResolveGcmNoncePolicy(kRealityServerGcmNoncePolicyCounter,
                                                 &tracker,
                                                 &policy,
                                                 &counter_next),
            "manual counter policy without a sample must fail");
    require(realityserverTls12RecordTrackerFeed(&tracker, records + short_len, 0),
            "zero-length tracker callback failed");
    ccs_len = buildRecord(kRecordChangeCipherSpec, &ccs, 1, records);
    require(realityserverTls12RecordTrackerFeed(&tracker, records, ccs_len), "exhaustion tracker CCS failed");
    tracker.next_sequence = UINT64_MAX;
    size_t protected_len = buildProtectedGcmRecord(UINT64_MAX, records);
    require(! realityserverTls12RecordTrackerFeed(&tracker, records, protected_len) && tracker.failed,
            "TLS sequence exhaustion must fail before wrap");
    realityserverTls12RecordTrackerDestroy(&tracker);
}

static sbuf_t *createPooledBuffer(buffer_pool_t *pool, const uint8_t *data, size_t len)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(pool);
    require(len <= sbufGetMaximumWriteableSize(buf), "partial-state test buffer is too large");
    sbufSetLength(buf, (uint32_t) len);
    memoryCopy(sbufGetMutablePtr(buf), data, len);
    return buf;
}

static void testLinestateDestroyClearsPartialTlsState(void)
{
    master_pool_t *large_master = masterpoolCreateWithCapacity(8);
    master_pool_t *small_master = masterpoolCreateWithCapacity(8);
    buffer_pool_t *pool = bufferpoolCreate(large_master, small_master, 8, 8192, 1024);
    uint32_t aligned_size = tunnelGetCorrectAlignedLineStateSize(sizeof(realityserver_lstate_t));
    realityserver_lstate_t *ls = memoryAllocateCacheAlignedZero(aligned_size);
    require(ls != NULL, "failed to allocate aligned RealityServer line state");
    realityserverLinestateInitialize(ls, pool);

    const uint8_t queued_upstream[]   = {0x16, 0x03, 0x03, 0x00, 0x20, 0xaa};
    const uint8_t queued_downstream[] = {0x16, 0x03, 0x03, 0x00, 0x20, 0xbb};
    bufferstreamPush(&ls->read_stream,
                     createPooledBuffer(pool, queued_upstream, sizeof(queued_upstream)));
    bufferstreamPush(&ls->downstream_tls_observe_stream,
                     createPooledBuffer(pool, queued_downstream, sizeof(queued_downstream)));

    uint8_t body[128];
    uint8_t handshake[160];
    uint8_t record[192];
    size_t body_len = buildClientHelloBody(body);
    size_t handshake_len = buildHandshake(kHandshakeClientHello, body, body_len, handshake);
    size_t record_len = buildRecord(kRecordHandshake, handshake, handshake_len, record);
    require(record_len > 12 &&
                realityserverTlsParserFeed(&ls->client_hello_parser, record, 12, &ls->tls_capture),
            "partial ClientHello accumulation failed");
    require(ls->client_hello_parser.handshake_body != NULL,
            "partial ClientHello did not allocate parser state");

    uint8_t random[32];
    for (uint8_t i = 0; i < sizeof(random); ++i)
    {
        random[i] = (uint8_t) (0x80U + i);
    }
    body_len      = buildServerHelloBody(body, random, false);
    handshake_len = buildHandshake(kHandshakeServerHello, body, body_len, handshake);
    record_len    = buildRecord(kRecordHandshake, handshake, handshake_len, record);
    require(record_len > 12 &&
                realityserverTlsParserFeed(&ls->server_hello_parser, record, 12, &ls->tls_capture),
            "partial ServerHello accumulation failed");
    require(ls->server_hello_parser.handshake_body != NULL,
            "partial ServerHello did not allocate parser state");

    reality_v2_record_profile_t profile;
    require(realityV2SelectRecordProfile(kRealityV2Tls12, 0xC02F, &profile),
            "partial-state tracker profile selection failed");
    require(realityserverTls12RecordTrackerSetProfile(&ls->client_record_tracker, &profile) &&
                realityserverTls12RecordTrackerSetProfile(&ls->server_record_tracker, &profile),
            "partial-state tracker configuration failed");
    require(realityserverTls12RecordTrackerFeed(&ls->client_record_tracker, record, 3) &&
                realityserverTls12RecordTrackerFeed(&ls->server_record_tracker, record, 2),
            "partial TLS record-header accumulation failed");
    require(ls->client_record_tracker.record_header_length == 3 &&
                ls->server_record_tracker.record_header_length == 2 &&
                bufferstreamGetBufLen(&ls->read_stream) != 0 &&
                bufferstreamGetBufLen(&ls->downstream_tls_observe_stream) != 0,
            "line state did not retain all intended partial parser/tracker data");
    memorySet(ls->session_id, 0xa7, sizeof(ls->session_id));
    memorySet(ls->c2s_key, 0xb8, sizeof(ls->c2s_key));

    realityserverLinestateDestroy(ls);
    const uint8_t *bytes = (const uint8_t *) ls;
    for (uint32_t i = 0; i < aligned_size; ++i)
    {
        require(bytes[i] == 0, "line-state destroy did not zero the complete aligned state");
    }

    memoryFreeAligned(ls);
    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large_master);
    masterpoolMakeEmpty(small_master);
    masterpoolDestroy(large_master);
    masterpoolDestroy(small_master);
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
    testFailedParsingAndTrackingPreserveBinding();
    testTls12PairedEpochActivationAndFullHandshakeOrdering();
    testTls12ResumedHandshakeOrdering();
    testTls12MissingFinishedRejectsAuthorization();
    testTls12RecordTrackerEveryCallbackSplit();
    testTls12RecordTrackerPatternsAndProfiles();
    testTls12RecordTrackerFailures();
    testLinestateDestroyClearsPartialTlsState();
    return 0;
}
