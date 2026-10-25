/*
 * Covers: VMess AEAD authentication, request/response headers and body framing.
 * Setup: Actual OpenSSL-backed codec, fixed independent Python provider vectors,
 * and V2Fly v5.53.0's published recursive-KDF known answer. No sockets are used.
 * Cases: Reusable AuthID candidate trials, timestamp boundaries, malformed headers,
 * AES/ChaCha/NONE modes, continuous SHAKE padding/masking, authenticated lengths,
 * corrupted EOF tags, full 16-bit lengths, strict exhaustion, actual two-wrap
 * sessions with independent SHAKE checkpoints, short IDs and packetaddr.
 * CTest: waterwall.vmess_crypto_unit in Debug and Release.
 * Regeneration: python3 tests/unittests/tunnels/vmess/generate_vectors.py
 */
#include "wwapi.h"

#include "VmessCommon/crypto.h"
#include "test_assert.h"
#include "vectors.h"

#define require(condition, message)              TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#define equal(actual, expected, length, message) TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, actual, expected, length, message)

static void testKdf(void)
{
    static const uint8_t      key[]      = "Demo Key for KDF Value Test";
    static const uint8_t      p1[]       = "Demo Path for KDF Value Test";
    static const uint8_t      p2[]       = "Demo Path for KDF Value Test2";
    static const uint8_t      p3[]       = "Demo Path for KDF Value Test3";
    const vmess_kdf_segment_t path[]     = {{p1, sizeof(p1) - 1}, {p2, sizeof(p2) - 1}, {p3, sizeof(p3) - 1}};
    const uint8_t             expected[] = {0x53, 0xe9, 0xd7, 0xe1, 0xbd, 0x7b, 0xd2, 0x50, 0x22, 0xb7, 0x1e,
                                            0xad, 0x07, 0xd8, 0xa5, 0x96, 0xef, 0xc8, 0xa8, 0x45, 0xc7, 0x88,
                                            0x86, 0x52, 0xfd, 0x68, 0x4b, 0x49, 0x03, 0xdc, 0x88, 0x92};
    uint8_t                   out[32];
    require(vmessKdf(key, sizeof(key) - 1, path, 3, out) == kWCryptoOk, "KDF failed");
    equal(out, expected, sizeof(out), "upstream recursive KDF known answer differs");
}

static void testHeaders(void)
{
    vmess_prepared_key_t key;
    require(vmessPrepareKey(vector_uuid, &key) == kWCryptoOk, "UUID preparation failed");
    equal(key.cmd_key, vector_cmd, 16, "CmdKey differs");
    equal(key.auth_key, vector_auth_key, 16, "AuthKey differs");
    vmess_auth_id_ctx_t auth = {0};
    require(vmessAuthIdInit(&auth) == kWCryptoOk, "AuthID context failed");
    uint64_t             timestamp = 0;
    vmess_prepared_key_t wrong     = key;
    wrong.auth_key[0] ^= 1;
    for (unsigned i = 0; i < 4; ++i)
    {
        require(vmessAuthIdCheck(&auth, &wrong, vector_request, UINT64_C(1700000000), &timestamp) ==
                    kWCryptoAuthenticationFailed,
                "wrong AuthID candidate matched");
        require(vmessAuthIdCheck(&auth, &key, vector_request, UINT64_C(1700000000), &timestamp) == kWCryptoOk,
                "valid AuthID failed after rejected candidate");
    }
    require(timestamp == UINT64_C(1700000000), "AuthID timestamp differs");
    require(vmessAuthIdCheck(&auth, &key, vector_request, timestamp + 120, &timestamp) == kWCryptoOk,
            "inclusive timestamp window failed");
    require(vmessAuthIdCheck(&auth, &key, vector_request, timestamp + 121, &timestamp) == kWCryptoRejectedKey,
            "recognized stale AuthID was not distinguished from unknown credentials");
    require(vmessAuthIdCheck(&auth, &key, vector_request, timestamp - 121, &timestamp) == kWCryptoRejectedKey,
            "future AuthID accepted");
    vmessAuthIdDestroy(&auth);
    require(auth.cipher == NULL, "AuthID context not cleared");

    uint16_t length = 0;
    require(vmessRequestLengthOpen(key.cmd_key, vector_request, vector_request + 16, vector_request + 34, &length) ==
                kWCryptoOk,
            "request length failed");
    require(length == sizeof(vector_plain_header), "request length differs");
    vmess_request_header_t header;
    require(vmessRequestHeaderOpen(key.cmd_key,
                                   vector_request,
                                   vector_request + 34,
                                   vector_request + 42,
                                   sizeof(vector_request) - 42,
                                   &header) == kWCryptoOk,
            "request header failed");
    require(header.version == 1 && header.command == 1 && header.security == 3 && header.options == 13 &&
                header.response == 61 && header.port == 443 && header.address_type == 1 && header.address_length == 4,
            "parsed header fields differ");
    const uint8_t address[] = {127, 0, 0, 1};
    equal(header.address, address, sizeof(address), "header destination differs");
    equal(header.key, vector_key, 16, "request body key differs");
    equal(header.iv, vector_iv, 16, "request body IV differs");
    require(vmessRequestHeaderOpen(key.cmd_key,
                                   vector_request_udp,
                                   vector_request_udp + 34,
                                   vector_request_udp + 42,
                                   sizeof(vector_request_udp) - 42,
                                   &header) == kWCryptoOk &&
                header.command == 2,
            "independent UDP request header failed");
    require(vmessRequestHeaderParse(vector_plain_header_udp, sizeof(vector_plain_header_udp), &header) == kWCryptoOk,
            "UDP plaintext request header failed");
    uint8_t tampered[sizeof(vector_request)];
    memcpy(tampered, vector_request, sizeof(tampered));
    tampered[33] ^= 1;
    require(vmessRequestLengthOpen(key.cmd_key, tampered, tampered + 16, tampered + 34, &length) ==
                kWCryptoAuthenticationFailed,
            "corrupt length tag authenticated");
    memcpy(tampered, vector_request, sizeof(tampered));
    tampered[sizeof(tampered) - 1] ^= 1;
    require(
        vmessRequestHeaderOpen(key.cmd_key, tampered, tampered + 34, tampered + 42, sizeof(tampered) - 42, &header) ==
            kWCryptoAuthenticationFailed,
        "corrupt header tag authenticated");
    const vmess_request_header_t zero = {0};
    equal(&header, &zero, sizeof(header), "failed header leaked parsed state");
    for (size_t truncated = 0; truncated < sizeof(vector_plain_header); ++truncated)
    {
        require(vmessRequestHeaderParse(vector_plain_header, truncated, &header) != kWCryptoOk,
                "truncated plaintext header accepted");
    }
    uint8_t response_key[16], response_iv[16], response[VMESS_RESPONSE_HEADER_SIZE];
    require(vmessResponseKeys(vector_key, vector_iv, response_key, response_iv) == kWCryptoOk,
            "response key derivation failed");
    require(vmessResponseHeaderSeal(response_key, response_iv, 61, response) == kWCryptoOk,
            "response header seal failed");
    equal(response, vector_response, sizeof(response), "independent response header vector differs");
}

static void testBodyVectors(void)
{
    vmess_body_ctx_t rx = {0}, tx = {0};
    const uint8_t    hello[] = "Hello VMess";
    uint8_t          sequence[31];
    for (size_t i = 0; i < sizeof(sequence); ++i)
    {
        sequence[i] = (uint8_t) i;
    }
    for (size_t i = 0; i < sizeof(vector_frames) / sizeof(vector_frames[0]); ++i)
    {
        const vmess_vector_t *vector = &vector_frames[i];
        if (vector->index == 0)
        {
            require(vmessBodyInit(&rx,
                                  vector_key,
                                  vector_iv,
                                  vector->security,
                                  vector->options,
                                  vector->command,
                                  false,
                                  kVmessCounterStrict) == kWCryptoOk,
                    "vector receiver initialization failed");
            require(vmessBodyInit(&tx,
                                  vector_key,
                                  vector_iv,
                                  vector->security,
                                  vector->options,
                                  vector->command,
                                  true,
                                  kVmessCounterStrict) == kWCryptoOk,
                    "vector sender initialization failed");
        }
        size_t   prefix_length = vmessBodyLengthSize(&rx);
        uint32_t wire_length   = 0;
        require(vmessBodyLengthOpen(&rx, vector->wire, prefix_length, &wire_length) == kWCryptoOk,
                "independent frame length failed");
        require(wire_length == vector->length - prefix_length, "decoded body length differs");
        uint8_t out[256];
        size_t  plaintext_length = 0;
        bool    eof              = false;
        require(
            vmessBodyOpen(&rx, vector->wire + prefix_length, wire_length, out, sizeof(out), &plaintext_length, &eof) ==
                kWCryptoOk,
            "independent body vector did not decrypt");
        const uint8_t *expected = vector->index == 0 ? hello : sequence;
        size_t expected_length  = vector->index == 0 ? sizeof(hello) - 1 : (vector->index == 1 ? sizeof(sequence) : 0);
        require(plaintext_length == expected_length && eof == (vector->index == 2), "body result differs");
        equal(out, expected, expected_length, "independent body plaintext differs");
        size_t emitted = 0;
        require(vmessBodySeal(&tx, expected, expected_length, eof, out, sizeof(out), &emitted) == kWCryptoOk,
                "frame seal failed");
        require(emitted == vector->length, "sealed frame length differs");
        equal(out, vector->wire, emitted - vector->padding, "independent sealed vector differs before random padding");
        if (vector->index == 2)
        {
            require(vmessBodySeal(&tx, hello, sizeof(hello) - 1, false, out, sizeof(out), &emitted) ==
                        kWCryptoInvalidState,
                    "payload accepted after EOF");
            vmessBodyDestroy(&rx);
            vmessBodyDestroy(&tx);
        }
    }
}

static void testClientHeaders(void)
{
    vmess_prepared_key_t key;
    require(vmessPrepareKey(vector_uuid, &key) == kWCryptoOk, "client UUID preparation failed");
    const uint8_t random[] = {1, 2, 3, 4};
    uint8_t       auth_id[16];
    require(vmessAuthIdCreate(&key, UINT64_C(1700000000), random, auth_id) == kWCryptoOk, "AuthID construction failed");
    equal(auth_id, vector_request, 16, "independent AuthID creation vector differs");
    require(vmessAuthIdCreate(&key, UINT64_MAX, random, auth_id) == kWCryptoInvalidArgument,
            "negative wire timestamp accepted");
    vmess_request_header_t header;
    require(vmessRequestHeaderParse(vector_plain_header, sizeof(vector_plain_header), &header) == kWCryptoOk,
            "client request model failed");
    uint8_t       output[VMESS_REQUEST_WIRE_MAX];
    size_t        length    = 0;
    const uint8_t padding[] = {0xee, 0xee, 0xee};
    require(vmessRequestHeaderSeal(key.cmd_key,
                                   vector_request,
                                   vector_request + 34,
                                   &header,
                                   padding,
                                   sizeof(padding),
                                   output,
                                   sizeof(output),
                                   &length) == kWCryptoOk,
            "client request seal failed");
    require(length == sizeof(vector_request), "client request wire length differs");
    equal(output, vector_request, length, "independent request seal differs");
    header.command = 2;
    require(vmessRequestHeaderSeal(key.cmd_key,
                                   vector_request,
                                   vector_request + 34,
                                   &header,
                                   padding,
                                   sizeof(padding),
                                   output,
                                   sizeof(output),
                                   &length) == kWCryptoOk,
            "client UDP request seal failed");
    equal(output, vector_request_udp, length, "independent UDP request seal differs");
    header.command        = 1;
    header.address_type   = 3;
    header.address_length = 16;
    for (size_t i = 0; i < 16; ++i)
    {
        header.address[i] = (uint8_t) i;
    }
    require(vmessRequestHeaderSeal(
                key.cmd_key, vector_request, vector_request + 34, &header, NULL, 0, output, sizeof(output), &length) ==
                kWCryptoOk,
            "client IPv6 request seal failed");
    require(length == sizeof(vector_request_ipv6), "IPv6 request size differs");
    equal(output, vector_request_ipv6, length, "independent IPv6 request seal differs");
    header.address_type   = 2;
    header.address_length = 255;
    memset(header.address, 'a', sizeof(header.address));
    uint8_t maximum_padding[15];
    for (size_t i = 0; i < sizeof(maximum_padding); ++i)
    {
        maximum_padding[i] = (uint8_t) i;
    }
    require(vmessRequestHeaderSeal(key.cmd_key,
                                   vector_request,
                                   vector_request + 34,
                                   &header,
                                   maximum_padding,
                                   sizeof(maximum_padding),
                                   output,
                                   sizeof(output),
                                   &length) == kWCryptoOk,
            "maximum domain/padding request rejected");
    require(length == VMESS_REQUEST_WIRE_MAX, "maximum request size differs");
    equal(output, vector_request_domain_max, length, "independent maximum request seal differs");
    vmess_request_header_t parsed;
    require(vmessRequestHeaderOpen(key.cmd_key,
                                   output,
                                   output + 34,
                                   output + VMESS_REQUEST_PREFIX_SIZE,
                                   length - VMESS_REQUEST_PREFIX_SIZE,
                                   &parsed) == kWCryptoOk,
            "maximum sealed request not accepted");
    require(parsed.address_length == 255 && parsed.address_type == 2, "maximum domain lost");
    require(vmessRequestHeaderSeal(key.cmd_key,
                                   vector_request,
                                   vector_request + 34,
                                   &header,
                                   maximum_padding,
                                   sizeof(maximum_padding),
                                   output,
                                   sizeof(output) - 1,
                                   &length) == kWCryptoInputTooLarge &&
                length == 0,
            "undersized request output accepted");
    require(vmessRequestHeaderSeal(key.cmd_key,
                                   vector_request,
                                   vector_request + 34,
                                   &header,
                                   maximum_padding,
                                   16,
                                   output,
                                   sizeof(output),
                                   &length) == kWCryptoInvalidArgument,
            "oversized header padding accepted");
    header.address[254] = 0;
    require(vmessRequestHeaderSeal(
                key.cmd_key, vector_request, vector_request + 34, &header, NULL, 0, output, sizeof(output), &length) ==
                kWCryptoInvalidArgument,
            "NUL in domain accepted");
    header.address_length = 0;
    require(vmessRequestHeaderSeal(
                key.cmd_key, vector_request, vector_request + 34, &header, NULL, 0, output, sizeof(output), &length) ==
                kWCryptoInvalidArgument,
            "empty domain accepted");
    header.address_type   = 1;
    header.address_length = 16;
    require(vmessRequestHeaderSeal(
                key.cmd_key, vector_request, vector_request + 34, &header, NULL, 0, output, sizeof(output), &length) ==
                kWCryptoInvalidArgument,
            "wrong literal address width accepted");
    header.address_length = 4;
    header.port           = 0;
    require(vmessRequestHeaderSeal(
                key.cmd_key, vector_request, vector_request + 34, &header, NULL, 0, output, sizeof(output), &length) ==
                kWCryptoInvalidArgument,
            "zero request port accepted");
    wCryptoZero(&key, sizeof(key));
    wCryptoZero(&header, sizeof(header));
    wCryptoZero(&parsed, sizeof(parsed));
}

static void testClientResponses(void)
{
    uint8_t key[16], iv[16];
    require(vmessResponseKeys(vector_key, vector_iv, key, iv) == kWCryptoOk, "client response keys failed");
    equal(key, vector_response_key, sizeof(key), "independent response key differs");
    equal(iv, vector_response_iv, sizeof(iv), "independent response IV differs");
    const struct
    {
        const uint8_t *wire;
        size_t         length;
        bool           valid_length;
        bool           valid_header;
    } cases[] = {
        {vector_response, sizeof(vector_response), true, true},
        {vector_response_command, sizeof(vector_response_command), true, true},
        {vector_response_command_max, sizeof(vector_response_command_max), true, true},
        {vector_response_wrong_marker, sizeof(vector_response_wrong_marker), true, false},
        {vector_response_short_command, sizeof(vector_response_short_command), true, false},
        {vector_response_zero_command, sizeof(vector_response_zero_command), true, false},
        {vector_response_too_short, sizeof(vector_response_too_short), false, false},
        {vector_response_too_large, sizeof(vector_response_too_large), false, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        uint16_t         length = UINT16_MAX;
        wcrypto_status_t status = vmessResponseLengthOpen(key, iv, cases[i].wire, &length);
        require((status == kWCryptoOk) == cases[i].valid_length, "response length validity differs");
        require(length == (cases[i].valid_length ? cases[i].length - 34 : 0), "response length result differs");
        status = vmessResponseHeaderOpen(key, iv, 61, cases[i].wire + 18, cases[i].length - 18);
        require((status == kWCryptoOk) == cases[i].valid_header, "response grammar/marker validity differs");
    }
    for (size_t truncated = 0; truncated < 20; ++truncated)
    {
        require(vmessResponseHeaderOpen(key, iv, 61, vector_response + 18, truncated) != kWCryptoOk,
                "truncated response accepted");
    }
    uint8_t tampered[sizeof(vector_response)];
    memcpy(tampered, vector_response, sizeof(tampered));
    tampered[17] ^= 1;
    uint16_t length = UINT16_MAX;
    require(vmessResponseLengthOpen(key, iv, tampered, &length) == kWCryptoAuthenticationFailed && length == 0,
            "corrupt response length tag accepted");
    memcpy(tampered, vector_response, sizeof(tampered));
    tampered[sizeof(tampered) - 1] ^= 1;
    require(vmessResponseHeaderOpen(key, iv, 61, tampered + 18, sizeof(tampered) - 18) == kWCryptoAuthenticationFailed,
            "corrupt response header tag accepted");
    const struct
    {
        uint8_t        security;
        uint8_t        options;
        const uint8_t *wire;
        size_t         length;
    } records[] = {
        {3, 13, vector_response_frame_3_13, sizeof(vector_response_frame_3_13)},
        {3, 29, vector_response_frame_3_29, sizeof(vector_response_frame_3_29)},
        {4, 13, vector_response_frame_4_13, sizeof(vector_response_frame_4_13)},
        {4, 29, vector_response_frame_4_29, sizeof(vector_response_frame_4_29)},
    };
    for (size_t i = 0; i < sizeof(records) / sizeof(records[0]); ++i)
    {
        vmess_body_ctx_t rx = {0};
        require(vmessBodyInit(&rx, key, iv, records[i].security, records[i].options, 1, false, kVmessCounterStrict) ==
                    kWCryptoOk,
                "response body init failed");
        if ((records[i].options & VMESS_OPTION_AUTH_LENGTH) != 0)
        {
            require(vmessBodySetLengthMaterial(&rx, vector_key, vector_iv) == kWCryptoOk,
                    "response authenticated-length material failed");
        }
        uint32_t wire_length = 0;
        size_t   prefix      = vmessBodyLengthSize(&rx);
        require(vmessBodyLengthOpen(&rx, records[i].wire, prefix, &wire_length) == kWCryptoOk &&
                    wire_length + prefix == records[i].length,
                "response body length differs");
        uint8_t output[256];
        size_t  plain_length = 0;
        bool    eof          = false;
        require(
            vmessBodyOpen(&rx, records[i].wire + prefix, wire_length, output, sizeof(output), &plain_length, &eof) ==
                    kWCryptoOk &&
                plain_length == 5 && ! eof,
            "response body decode failed");
        equal(output, "reply", 5, "response body vector differs");
        vmess_body_ctx_t tx = {0};
        require(vmessBodyInit(&tx, key, iv, records[i].security, records[i].options, 1, true, kVmessCounterStrict) ==
                    kWCryptoOk,
                "response body sender init failed");
        if ((records[i].options & VMESS_OPTION_AUTH_LENGTH) != 0)
        {
            require(vmessBodySetLengthMaterial(&tx, vector_key, vector_iv) == kWCryptoOk,
                    "response sender authenticated-length material failed");
        }
        size_t emitted = 0;
        require(vmessBodySeal(&tx, (const uint8_t *) "reply", 5, false, output, sizeof(output), &emitted) ==
                        kWCryptoOk &&
                    emitted == records[i].length,
                "response body sender size differs");
        equal(output, records[i].wire, prefix + 5 + 16, "independent response seal differs before random padding");
        vmessBodyDestroy(&tx);
        vmessBodyDestroy(&rx);
    }
    wCryptoZero(key, sizeof(key));
    wCryptoZero(iv, sizeof(iv));
}

static void testEofAndCounter(void)
{
    uint8_t          output[256];
    size_t           output_length = 0;
    vmess_body_ctx_t rx = {0}, tx = {0};
    require(vmessBodyInit(&tx, vector_key, vector_iv, 3, 1, 1, true, kVmessCounterStrict) == kWCryptoOk,
            "sender init failed");
    tx.counter = UINT16_MAX;
    require(vmessBodySeal(&tx, (const uint8_t *) "x", 1, false, output, sizeof(output), &output_length) ==
                kVmessCounterExhausted,
            "last outgoing nonce used for data");
    require(vmessBodySeal(&tx, NULL, 0, true, output, sizeof(output), &output_length) == kWCryptoOk,
            "reserved outgoing nonce could not seal EOF");
    require(vmessBodyInit(&rx, vector_key, vector_iv, 3, 1, 1, false, kVmessCounterStrict) == kWCryptoOk,
            "receiver init failed");
    rx.counter      = UINT16_MAX;
    uint32_t length = 0;
    require(vmessBodyLengthOpen(&rx, output, 2, &length) == kWCryptoOk, "EOF length failed");
    output[output_length - 1] ^= 1;
    size_t plain_length = 0;
    bool   eof          = false;
    require(vmessBodyOpen(&rx, output + 2, length, NULL, 0, &plain_length, &eof) == kWCryptoAuthenticationFailed,
            "corrupted EOF tag was not authenticated");
    require(! eof && rx.failed, "corrupt EOF advanced connection state");
    vmessBodyDestroy(&rx);
    vmessBodyDestroy(&tx);

    require(vmessBodyInit(&rx, vector_key, vector_iv, 3, 1, 1, false, kVmessCounterStrict) == kWCryptoOk,
            "last-frame init failed");
    rx.counter = UINT16_MAX;
    require(vmessBodyLengthOpen(&rx, vector_last_counter, 2, &length) == kWCryptoOk, "last inbound length rejected");
    require(vmessBodyOpen(&rx, vector_last_counter + 2, length, output, sizeof(output), &plain_length, &eof) ==
                kWCryptoOk,
            "counter 65535 inbound data rejected");
    equal(output, "last", 4, "last inbound nonce plaintext differs");
    require(vmessBodyLengthOpen(&rx, vector_last_counter, 2, &length) == kVmessCounterExhausted,
            "inbound nonce counter wrapped");
    vmessBodyDestroy(&rx);

    const uint8_t *last_frames[] = {vector_last_counter_auth_aes, vector_last_counter_auth_chacha};
    for (uint8_t security = 3; security <= 4; ++security)
    {
        const uint8_t *frame = last_frames[security - 3];
        require(vmessBodyInit(&rx, vector_key, vector_iv, security, 29, 1, false, kVmessCounterStrict) == kWCryptoOk,
                "authenticated last-frame receiver init failed");
        rx.counter = UINT16_MAX;
        require(vmessBodyLengthOpen(&rx, frame, 18, &length) == kWCryptoOk,
                "authenticated last inbound length rejected");
        require(vmessBodyOpen(&rx, frame + 18, length, output, sizeof(output), &plain_length, &eof) == kWCryptoOk &&
                    plain_length == 4 && ! eof,
                "authenticated counter 65535 inbound data rejected");
        equal(output, "last", 4, "authenticated final nonce plaintext differs");
        require(vmessBodyLengthOpen(&rx, frame, 18, &length) == kVmessCounterExhausted,
                "authenticated inbound nonce wrapped");
        vmessBodyDestroy(&rx);
        require(vmessBodyInit(&tx, vector_key, vector_iv, security, 29, 1, true, kVmessCounterStrict) == kWCryptoOk,
                "authenticated final sender init failed");
        tx.counter = UINT16_MAX;
        require(vmessBodySeal(&tx, (const uint8_t *) "x", 1, false, output, sizeof(output), &output_length) ==
                    kVmessCounterExhausted,
                "authenticated final outgoing nonce used for data");
        require(vmessBodySeal(&tx, NULL, 0, true, output, sizeof(output), &output_length) == kWCryptoOk,
                "authenticated reserved outgoing nonce could not seal EOF");
        vmessBodyDestroy(&tx);
    }
}

static void testLargeAndFailure(void)
{
    uint8_t *plain = memoryAllocate(65535);
    uint8_t *wire  = memoryAllocate(VMESS_MAX_BODY_WIRE_SIZE + 18);
    memset(plain, 'Z', 65535);
    vmess_body_ctx_t tx = {0}, rx = {0};
    require(vmessBodyInit(&tx, vector_key, vector_iv, 3, 17, 1, true, kVmessCounterStrict) == kWCryptoOk,
            "large sender init failed");
    require(vmessBodyInit(&rx, vector_key, vector_iv, 3, 17, 1, false, kVmessCounterStrict) == kWCryptoOk,
            "large receiver init failed");
    size_t total = 0;
    require(vmessBodySeal(&tx, plain, 65535, false, wire, VMESS_MAX_BODY_WIRE_SIZE + 18, &total) == kWCryptoOk,
            "full 16-bit authenticated-length payload rejected");
    require(total == 65569, "full length wrapped during sealing");
    equal(wire, vector_large_prefix, 18, "independent maximum length prefix differs");
    sha256_hash_t hash;
    require(wCryptoSHA256(&hash, wire, total) == kWCryptoOk, "large frame digest failed");
    equal(hash.bytes, vector_large_hash, 32, "independent maximum length ciphertext differs");
    uint32_t length = 0;
    require(vmessBodyLengthOpen(&rx, wire, 18, &length) == kWCryptoOk && length == 65551,
            "authenticated length tag offset overflowed");
    size_t decoded = 0;
    bool   eof     = false;
    require(vmessBodyOpen(&rx, wire + 18, length, wire + 18, length, &decoded, &eof) == kWCryptoOk,
            "maximum body in-place open failed");
    require(decoded == 65535 && ! eof, "maximum body result differs");
    equal(wire + 18, plain, decoded, "maximum body bytes differ");
    vmessBodyDestroy(&rx);
    vmessBodyDestroy(&tx);

    require(vmessBodyInit(&tx, vector_key, vector_iv, 4, 17, 1, true, kVmessCounterStrict) == kWCryptoOk,
            "failure sender init failed");
    require(vmessBodyInit(&rx, vector_key, vector_iv, 4, 17, 1, false, kVmessCounterStrict) == kWCryptoOk,
            "failure receiver init failed");
    require(vmessBodySeal(&tx, plain, 32, false, wire, VMESS_MAX_BODY_WIRE_SIZE + 18, &total) == kWCryptoOk,
            "failure frame seal failed");
    require(vmessBodyLengthOpen(&rx, wire, 18, &length) == kWCryptoOk, "failure frame length failed");
    wire[total - 1] ^= 1;
    memset(plain, 0xa5, 32);
    require(vmessBodyOpen(&rx, wire + 18, length, plain, 32, &decoded, &eof) == kWCryptoAuthenticationFailed,
            "corrupt data tag authenticated");
    uint8_t zeros[32] = {0};
    equal(plain, zeros, 32, "unauthenticated plaintext survived failure");
    vmessBodyDestroy(&rx);
    vmessBodyDestroy(&tx);
    memoryFree(wire);
    memoryFree(plain);
}

static void testModes(void)
{
    for (uint8_t security = 3; security <= 5; ++security)
    {
        for (uint8_t command = 1; command <= 2; ++command)
        {
            for (unsigned options = 0; options <= UINT8_MAX; ++options)
            {
                bool expected = options == 1 || options == 5;
                if (security == VMESS_SECURITY_NONE)
                {
                    expected |= command == 1 ? options == 0 : options == 13;
                }
                else
                {
                    expected |= options == 13 || options == 17 || options == 21 || options == 29;
                }
                require(vmessModeValid(security, (uint8_t) options, command) == expected,
                        "shared mode validation differs from supported option matrix");
            }
        }
    }
    vmess_body_ctx_t ctx = {0};
    require(vmessBodyInit(&ctx, vector_key, vector_iv, 5, 0, 1, true, kVmessCounterStrict) == kWCryptoOk && ctx.raw,
            "raw NONE TCP rejected");
    uint8_t out[8];
    size_t  length = 0;
    require(vmessBodySeal(&ctx, (const uint8_t *) "raw", 3, false, out, sizeof(out), &length) == kWCryptoOk &&
                length == 3,
            "raw NONE framed unexpectedly");
    equal(out, "raw", 3, "raw NONE bytes differ");
    require(vmessBodySeal(&ctx, NULL, 0, true, NULL, 0, &length) == kWCryptoOk && length == 0,
            "raw NONE emitted wire EOF");
    vmessBodyDestroy(&ctx);
    const uint8_t bad[][3] = {
        {5, 0, 2}, {5, 13, 1}, {5, 17, 1}, {1, 1, 1}, {6, 1, 1}, {3, 9, 1}, {3, 3, 1}, {3, 1, 3}, {3, 0, 1}};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
    {
        require(
            vmessBodyInit(&ctx, vector_key, vector_iv, bad[i][0], bad[i][1], bad[i][2], false, kVmessCounterStrict) ==
                kWCryptoInvalidArgument,
            "unsupported mode/options accepted");
        vmessBodyDestroy(&ctx);
    }
}

static void testAutoSecurity(void)
{
    for (unsigned facts = 0; facts < 8; ++facts)
    {
        bool             accelerated = (facts & 1U) != 0;
        bool             aes         = (facts & 2U) != 0;
        bool             chacha      = (facts & 4U) != 0;
        uint8_t          selected    = UINT8_MAX;
        wcrypto_status_t status      = vmessAutoSecuritySelect(accelerated, aes, chacha, &selected);
        require((status == kWCryptoOk) == (aes || chacha), "auto selection availability differs");
        uint8_t expected = aes && (accelerated || ! chacha) ? VMESS_SECURITY_AES128_GCM
                           : chacha                         ? VMESS_SECURITY_CHACHA20_POLY1305
                                                            : 0;
        require(selected == expected, "auto selection ignored supplied capability facts");
    }
    require(vmessCipherAvailable(VMESS_SECURITY_AES128_GCM), "test provider lacks AES-GCM");
    require(vmessCipherAvailable(VMESS_SECURITY_CHACHA20_POLY1305), "test provider lacks ChaCha");
    require(vmessCipherAvailable(VMESS_SECURITY_NONE) && ! vmessCipherAvailable(0),
            "explicit provider mode classification differs");
    uint8_t selected = 0;
    require(vmessAutoSecurity(&selected) == kWCryptoOk &&
                (selected == VMESS_SECURITY_AES128_GCM || selected == VMESS_SECURITY_CHACHA20_POLY1305) &&
                vmessCipherAvailable(selected),
            "runtime auto selected an unavailable or unencrypted algorithm");
}

static void testShortIds(void)
{
    const struct
    {
        const char    *text;
        const uint8_t *expected;
    } cases[] = {
        {"test", vector_short_id_test},
        {"waterwall", vector_short_id_waterwall},
        {"a", vector_short_id_one},
        {"\xdb\xb1\xdb\xb2\xdb\xb3", vector_short_id_persian},
        {"\xc3\xa9", vector_short_id_composed},
        {"e\xcc\x81", vector_short_id_decomposed},
        {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", vector_short_id_max},
    };
    uint8_t       result[16];
    const uint8_t zero[16] = {0};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        require(vmessNormalizeId(cases[i].text, strlen(cases[i].text), result) == kWCryptoOk,
                "valid exact short ID rejected");
        equal(result, cases[i].expected, sizeof(result), "independent UUIDv5 mapping differs");
    }
    const char *uuids[] = {"00010203-0405-0607-0809-0a0b0c0d0e0f", "000102030405060708090A0B0C0D0E0F"};
    for (size_t i = 0; i < sizeof(uuids) / sizeof(uuids[0]); ++i)
    {
        require(vmessNormalizeId(uuids[i], strlen(uuids[i]), result) == kWCryptoOk, "strict UUID rejected");
        equal(result, vector_uuid, sizeof(result), "strict UUID bytes changed");
    }
    char multibyte[32];
    for (size_t i = 0; i < sizeof(multibyte); i += 2)
    {
        multibyte[i]     = (char) 0xc3;
        multibyte[i + 1] = (char) 0xa9;
    }
    require(vmessNormalizeId(multibyte, 30, result) == kWCryptoOk, "30 UTF-8 bytes rejected");
    require(vmessNormalizeId(multibyte, 31, result) == kWCryptoInvalidArgument, "31 UTF-8 bytes accepted");
    require(vmessNormalizeId(multibyte, 32, result) == kWCryptoInvalidArgument, "32 non-UUID UTF-8 bytes accepted");
    const char *invalid[] = {"",
                             "\xc0\xaf",
                             "\xc2",
                             "\x80",
                             "\xe0\x80\xaf",
                             "\xed\xa0\x80",
                             "\xf0\x80\x80\xaf",
                             "\xf4\x90\x80\x80",
                             "\xf5\x80\x80\x80",
                             "1234567890123456789012345678901",
                             "g2345678901234567890123456789012",
                             "00010203_0405-0607-0809-0a0b0c0d0e0f",
                             "00010203-0405-0607-0809-0a0b0c0d0e0g"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        memset(result, 0xa5, sizeof(result));
        require(vmessNormalizeId(invalid[i], strlen(invalid[i]), result) == kWCryptoInvalidArgument,
                "invalid ID encoding/length accepted");
        equal(result, zero, sizeof(result), "invalid normalization retained credential bytes");
    }
    const char embedded_nul[] = {'a', '\0', 'b'};
    require(vmessNormalizeId(embedded_nul, sizeof(embedded_nul), result) == kWCryptoInvalidArgument,
            "embedded NUL truncated instead of rejected");
    const char uuid_nul[36] = "000102030405060708090A0B0C0D0E0F\0abc";
    require(vmessNormalizeId(uuid_nul, sizeof(uuid_nul), result) == kWCryptoInvalidArgument,
            "UUID-sized ID accepted a compact prefix before embedded NUL");
    require(vmessNormalizeId("test ", 5, result) == kWCryptoOk && memcmp(result, vector_short_id_test, 16) != 0,
            "short ID whitespace was trimmed");
    require(vmessNormalizeId("TEST", 4, result) == kWCryptoOk && memcmp(result, vector_short_id_test, 16) != 0,
            "short ID case was folded");
}

static void testPacketAddr(void)
{
    const struct
    {
        const uint8_t *wire;
        size_t         size;
        uint8_t        family;
        uint16_t       port;
    } cases[] = {
        {vector_packetaddr_v4, sizeof(vector_packetaddr_v4), 1, 5353},
        {vector_packetaddr_v6, sizeof(vector_packetaddr_v6), 3, 443},
    };
    uint8_t output[64];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        vmess_packet_addr_t address;
        size_t              header_length = 0;
        require(vmessPacketAddrDecode(cases[i].wire, cases[i].size, &address, &header_length) == kWCryptoOk &&
                    header_length == cases[i].size && address.address_type == cases[i].family &&
                    address.port == cases[i].port,
                "independent empty packetaddr envelope differs");
        equal(address.address, cases[i].wire + 1, cases[i].size - 3, "packetaddr IP bytes differ");
        require(vmessPacketAddrHeaderSize(&address) == cases[i].size, "packetaddr envelope size differs");
        require(vmessPacketAddrEncode(&address, output, sizeof(output), &header_length) == kWCryptoOk,
                "packetaddr encoding failed");
        equal(output, cases[i].wire, cases[i].size, "independent packetaddr encoding differs");
        require(vmessPacketAddrEncode(&address, output, cases[i].size - 1, &header_length) == kWCryptoInputTooLarge &&
                    header_length == 0,
                "packetaddr output capacity not enforced");
        for (size_t truncated = 0; truncated < cases[i].size; ++truncated)
        {
            require(vmessPacketAddrDecode(cases[i].wire, truncated, &address, &header_length) ==
                            kWCryptoInvalidArgument &&
                        header_length == 0,
                    "truncated packetaddr envelope accepted");
        }
        memcpy(output, cases[i].wire, cases[i].size);
        output[cases[i].size] = 0xa5;
        require(vmessPacketAddrDecode(output, cases[i].size + 1, &address, &header_length) == kWCryptoOk &&
                    header_length == cases[i].size && output[header_length] == 0xa5,
                "packetaddr payload boundary lost");
        address.port = 0;
        require(vmessPacketAddrEncode(&address, output, sizeof(output), &header_length) == kWCryptoInvalidArgument,
                "packetaddr destination port zero accepted");
        memcpy(output, cases[i].wire, cases[i].size);
        memset(output + cases[i].size - 2, 0, 2);
        require(vmessPacketAddrDecode(output, cases[i].size, &address, &header_length) == kWCryptoInvalidArgument,
                "packetaddr decoded destination port zero accepted");
    }
    vmess_packet_addr_t invalid = {.address_type = 2, .port = 443};
    size_t              length  = 1;
    require(vmessPacketAddrHeaderSize(&invalid) == 0 &&
                vmessPacketAddrEncode(&invalid, output, sizeof(output), &length) == kWCryptoInvalidArgument,
            "packetaddr domain invented an envelope extension");
    for (unsigned family = 0; family <= 255; ++family)
    {
        if (family == 1 || family == 2)
            continue;
        memset(output, 0xa5, sizeof(output));
        output[0] = (uint8_t) family;
        require(vmessPacketAddrDecode(output, sizeof(output), &invalid, &length) == kWCryptoInvalidArgument,
                "unsupported packetaddr wire family accepted");
    }

    vmess_request_header_t header;
    require(vmessRequestHeaderParse(vector_plain_header_udp, sizeof(vector_plain_header_udp), &header) == kWCryptoOk,
            "packetaddr header seed failed");
    header.address_type   = 2;
    header.address_length = sizeof(VMESS_PACKETADDR_DOMAIN) - 1;
    memcpy(header.address, VMESS_PACKETADDR_DOMAIN, header.address_length);
    header.port = 0;
    require(vmessIsPacketAddrDomain(header.address, header.address_length) &&
                ! vmessIsPacketAddrDomain(header.address, header.address_length - 1) &&
                ! vmessIsPacketAddrDomain(NULL, 0),
            "reserved domain predicate widened its exact match");
    require(vmessRequestIsPacketAddr(&header), "packetaddr marker was not recognized");
    vmess_prepared_key_t key;
    require(vmessPrepareKey(vector_uuid, &key) == kWCryptoOk, "packetaddr request key failed");
    uint8_t wire[VMESS_REQUEST_WIRE_MAX];
    require(vmessRequestHeaderSeal(
                key.cmd_key, vector_request, vector_request + 34, &header, NULL, 0, wire, sizeof(wire), &length) ==
                kWCryptoOk,
            "exact UDP packetaddr zero-port marker rejected");
    require(length == sizeof(vector_request_packetaddr), "packetaddr request length differs");
    equal(wire, vector_request_packetaddr, length, "independent packetaddr request differs");
    vmess_request_header_t decoded;
    require(vmessRequestHeaderOpen(key.cmd_key, wire, wire + 34, wire + 42, length - 42, &decoded) == kWCryptoOk &&
                vmessRequestIsPacketAddr(&decoded),
            "sealed packetaddr zero-port marker rejected by parser");
    const struct
    {
        const uint8_t *wire;
        size_t         length;
        uint8_t        command;
        uint16_t       port;
    } invalid_markers[] = {
        {vector_request_packetaddr_udp_wrong_port, sizeof(vector_request_packetaddr_udp_wrong_port), 2, 53},
        {vector_request_packetaddr_tcp_wrong_port, sizeof(vector_request_packetaddr_tcp_wrong_port), 1, 443},
        {vector_request_packetaddr_tcp_zero_port, sizeof(vector_request_packetaddr_tcp_zero_port), 1, 0},
    };
    const vmess_request_header_t empty_header = {0};
    for (size_t i = 0; i < sizeof(invalid_markers) / sizeof(invalid_markers[0]); ++i)
    {
        const uint8_t *invalid_wire = invalid_markers[i].wire;
        require(vmessRequestHeaderOpen(key.cmd_key,
                                       invalid_wire,
                                       invalid_wire + 34,
                                       invalid_wire + 42,
                                       invalid_markers[i].length - 42,
                                       &decoded) == kWCryptoInvalidArgument,
                "authenticated malformed reserved domain accepted by parser");
        equal(&decoded, &empty_header, sizeof(decoded), "rejected reserved domain retained parsed state");
        header.command = invalid_markers[i].command;
        header.port    = invalid_markers[i].port;
        require(
            ! vmessRequestIsPacketAddr(&header) &&
                vmessRequestHeaderSeal(
                    key.cmd_key, vector_request, vector_request + 34, &header, NULL, 0, wire, sizeof(wire), &length) ==
                    kWCryptoInvalidArgument &&
                length == 0,
            "malformed reserved domain accepted by sealer");
    }
    header.command = 2;
    header.port    = 0;
    require(vmessRequestHeaderOpen(key.cmd_key,
                                   vector_request_zero_port,
                                   vector_request_zero_port + 34,
                                   vector_request_zero_port + 42,
                                   sizeof(vector_request_zero_port) - 42,
                                   &decoded) == kWCryptoInvalidArgument,
            "authenticated ordinary port-zero header accepted by parser");
    header.command = 1;
    require(! vmessRequestIsPacketAddr(&header) &&
                vmessRequestHeaderSeal(
                    key.cmd_key, vector_request, vector_request + 34, &header, NULL, 0, wire, sizeof(wire), &length) ==
                    kWCryptoInvalidArgument,
            "TCP marker widened the port-zero exception");
    header.command = 2;
    header.address[0] ^= 1;
    require(! vmessRequestIsPacketAddr(&header) &&
                vmessRequestHeaderSeal(
                    key.cmd_key, vector_request, vector_request + 34, &header, NULL, 0, wire, sizeof(wire), &length) ==
                    kWCryptoInvalidArgument,
            "nonexact magic domain widened the port-zero exception");
    wCryptoZero(&key, sizeof(key));
    wCryptoZero(&header, sizeof(header));
    wCryptoZero(&decoded, sizeof(decoded));
}

static void testPacketAddrLimits(void)
{
    uint8_t      *plain      = memoryAllocate(VMESS_MAX_BODY_WIRE_SIZE);
    uint8_t      *wire       = memoryAllocate(VMESS_MAX_BODY_WIRE_SIZE + 18);
    const uint8_t profiles[] = {1, 5, 13, 17, 21, 29};
    for (uint8_t security = 3; security <= 5; ++security)
    {
        for (size_t profile = 0; profile < sizeof(profiles); ++profile)
        {
            uint8_t options = profiles[profile];
            if (! vmessModeValid(security, options, 2))
                continue;
            for (uint8_t family = 1; family <= 3; family += 2)
            {
                vmess_packet_addr_t address = {.address_type = family, .port = 443};
                address.address[0]          = family == 1 ? 192 : 0x20;
                vmess_body_ctx_t tx         = {0};
                require(vmessBodyInit(&tx, vector_key, vector_iv, security, options, 2, true, kVmessCounterWrap) ==
                            kWCryptoOk,
                        "packetaddr size sender initialization failed");
                size_t envelope = vmessPacketAddrHeaderSize(&address);
                size_t body_max = vmessBodyMaxPlaintext(&tx);
                size_t expected = UINT16_MAX + ((options & VMESS_OPTION_AUTH_LENGTH) != 0 ? 16U : 0U) -
                                  (security == VMESS_SECURITY_NONE ? 0U : 16U) -
                                  ((options & VMESS_OPTION_PADDING) != 0 ? 63U : 0U);
                require(body_max == expected && body_max > envelope, "packetaddr body maximum changed unexpectedly");
                memset(plain, 0xa5, body_max + 1);
                size_t header_length = 0, wire_length = 0;
                require(vmessPacketAddrEncode(&address, plain, body_max, &header_length) == kWCryptoOk &&
                            header_length == envelope && body_max - envelope == expected - (family == 1 ? 7U : 19U),
                        "packetaddr application maximum omitted exact envelope");
                require(vmessBodySeal(&tx, plain, body_max, false, wire, VMESS_MAX_BODY_WIRE_SIZE + 18, &wire_length) ==
                            kWCryptoOk,
                        "maximum packetaddr application datagram rejected");
                require(
                    vmessBodySeal(&tx, plain, body_max + 1, false, wire, VMESS_MAX_BODY_WIRE_SIZE + 18, &wire_length) ==
                            kWCryptoInputTooLarge &&
                        wire_length == 0,
                    "oversized packetaddr datagram split or accepted");
                vmessBodyDestroy(&tx);
            }
        }
    }
    memoryFree(wire);
    memoryFree(plain);
}

static void testActualCounterWrap(void)
{
    size_t        checkpoint = 0;
    const uint8_t profiles[] = {1, 5, 13, 17, 21, 29};
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        const uint8_t *key = direction == 0 ? vector_key : vector_response_key;
        const uint8_t *iv  = direction == 0 ? vector_iv : vector_response_iv;
        for (uint8_t security = 3; security <= 4; ++security)
        {
            for (size_t profile = 0; profile < sizeof(profiles); ++profile)
            {
                uint8_t          options = profiles[profile];
                vmess_body_ctx_t tx = {0}, rx = {0};
                require(vmessBodyInit(&tx, key, iv, security, options, 1, true, kVmessCounterWrap) == kWCryptoOk &&
                            vmessBodyInit(&rx, key, iv, security, options, 1, false, kVmessCounterWrap) == kWCryptoOk,
                        "actual-wrap codec initialization failed");
                if (direction != 0 && (options & VMESS_OPTION_AUTH_LENGTH) != 0)
                {
                    require(vmessBodySetLengthMaterial(&tx, vector_key, vector_iv) == kWCryptoOk &&
                                vmessBodySetLengthMaterial(&rx, vector_key, vector_iv) == kWCryptoOk,
                            "wrap response-length material failed");
                }
                for (uint32_t ordinal = 0; ordinal < 131074; ++ordinal)
                {
                    uint8_t  wire[128], plain[8];
                    size_t   wire_length = 0, plain_length = 0;
                    uint32_t body_length = 0;
                    bool     eof         = false;
                    require(tx.counter == (ordinal & UINT16_MAX) && rx.counter == tx.counter,
                            "wrap ordinal is not bounded modulo 65536");
                    require(vmessBodySeal(&tx, (const uint8_t *) "x", 1, false, wire, sizeof(wire), &wire_length) ==
                                kWCryptoOk,
                            "actual-wrap seal failed");
                    const vmess_wrap_vector_t *vector = &vector_wrap_checkpoints[checkpoint];
                    if (vector->direction == direction && vector->security == security && vector->options == options &&
                        vector->ordinal == ordinal)
                    {
                        require(wire_length == vector->length + vector->padding, "wrap checkpoint frame size differs");
                        equal(
                            wire, vector->wire, vector->length, "independent continuous-SHAKE wrap checkpoint differs");
                        ++checkpoint;
                    }
                    size_t prefix = vmessBodyLengthSize(&rx);
                    require(vmessBodyLengthOpen(&rx, wire, prefix, &body_length) == kWCryptoOk &&
                                body_length + prefix == wire_length && rx.pending &&
                                rx.counter == (ordinal & UINT16_MAX),
                            "split body lost pending length or advanced ordinal early");
                    require(vmessBodyOpen(&rx, wire + prefix, body_length, plain, sizeof(plain), &plain_length, &eof) ==
                                    kWCryptoOk &&
                                plain_length == 1 && plain[0] == 'x' && ! eof && ! rx.pending &&
                                rx.counter == tx.counter,
                            "actual-wrap authenticated delivery failed");
                }
                uint8_t  wire[128];
                size_t   wire_length = 0, plain_length = 0;
                uint32_t body_length = 0;
                bool     eof         = false;
                require(vmessBodySeal(&tx, NULL, 0, true, wire, sizeof(wire), &wire_length) == kWCryptoOk,
                        "EOF after two actual wraps failed to seal");
                size_t prefix = vmessBodyLengthSize(&rx);
                require(vmessBodyLengthOpen(&rx, wire, prefix, &body_length) == kWCryptoOk,
                        "EOF length after wraps failed");
                require(vmessBodyOpen(&rx, wire + prefix, body_length, NULL, 0, &plain_length, &eof) == kWCryptoOk &&
                            eof && rx.ended && tx.ended,
                        "EOF after wraps was not authenticated");
                require(vmessBodySeal(&tx, (const uint8_t *) "x", 1, false, wire, sizeof(wire), &wire_length) ==
                            kWCryptoInvalidState,
                        "ended wrap session accepted another record");
                vmessBodyDestroy(&tx);
                vmessBodyDestroy(&rx);
            }
        }
    }
    require(checkpoint == sizeof(vector_wrap_checkpoints) / sizeof(vector_wrap_checkpoints[0]),
            "not every independent wrap checkpoint was exercised");
}

static void testWrapBoundaryFailure(void)
{
    for (uint8_t security = 3; security <= 4; ++security)
    {
        for (unsigned side = 0; side < 2; ++side)
        {
            for (unsigned failure = 0; failure < 4; ++failure)
            {
                vmess_body_ctx_t tx = {0}, rx = {0};
                require(vmessBodyInit(&tx, vector_key, vector_iv, security, 29, 1, true, kVmessCounterWrap) ==
                                kWCryptoOk &&
                            vmessBodyInit(&rx, vector_key, vector_iv, security, 29, 1, false, kVmessCounterWrap) ==
                                kWCryptoOk,
                        "wrap failure initialization failed");
                /* Seeded ordinal complements actual from-zero continuity above. */
                rx.counter = tx.counter = side == 0 ? UINT16_MAX : 0;
                uint8_t  wire[128], plain[8];
                size_t   wire_length = 0, plain_length = 0;
                uint32_t body_length = 0;
                bool     eof         = false;
                bool     termination = failure >= 2;
                require(vmessBodySeal(&tx,
                                      termination ? NULL : (const uint8_t *) "x",
                                      termination ? 0 : 1,
                                      termination,
                                      wire,
                                      sizeof(wire),
                                      &wire_length) == kWCryptoOk,
                        "boundary frame refused under wrap");
                if (failure == 0)
                {
                    wire[17] ^= 1;
                    require(vmessBodyLengthOpen(&rx, wire, 18, &body_length) == kWCryptoAuthenticationFailed &&
                                rx.failed && body_length == 0,
                            "bad boundary length tag authenticated");
                    require(vmessBodyLengthOpen(&rx, wire, 18, &body_length) == kWCryptoInvalidState,
                            "failed boundary length context retried");
                }
                else
                {
                    require(vmessBodyLengthOpen(&rx, wire, 18, &body_length) == kWCryptoOk,
                            "boundary body length failed");
                    if (failure < 3)
                    {
                        wire[18 + (termination ? 0 : 1) + 15] ^= 1;
                    }
                    memset(plain, 0xa5, sizeof(plain));
                    wcrypto_status_t status =
                        vmessBodyOpen(&rx, wire + 18, body_length, plain, sizeof(plain), &plain_length, &eof);
                    if (failure == 3)
                    {
                        require(status == kWCryptoOk && eof && rx.ended && tx.ended, "valid boundary EOF rejected");
                    }
                    else
                    {
                        require(status == kWCryptoAuthenticationFailed && rx.failed && ! eof && plain_length == 0,
                                "bad body/EOF tag accepted at wrap boundary");
                        if (! termination)
                            require(plain[0] == 0, "unauthenticated boundary plaintext survived");
                        require(vmessBodyOpen(&rx, wire + 18, body_length, plain, sizeof(plain), &plain_length, &eof) ==
                                    kWCryptoInvalidState,
                                "failed boundary body context retried");
                    }
                }
                vmessBodyDestroy(&tx);
                vmessBodyDestroy(&rx);
            }
        }
    }
}

int main(void)
{
    testCaseSet("vmess_crypto_test");
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");
    require(globalstateInitializeSecureRandom() && frandGlobalInit(), "random initialization failed");
    TEST_RUN_CASE(testKdf);
    TEST_RUN_CASE(testHeaders);
    TEST_RUN_CASE(testClientHeaders);
    TEST_RUN_CASE(testClientResponses);
    TEST_RUN_CASE(testBodyVectors);
    TEST_RUN_CASE(testEofAndCounter);
    TEST_RUN_CASE(testLargeAndFailure);
    TEST_RUN_CASE(testModes);
    TEST_RUN_CASE(testAutoSecurity);
    TEST_RUN_CASE(testShortIds);
    TEST_RUN_CASE(testPacketAddr);
    TEST_RUN_CASE(testPacketAddrLimits);
    TEST_RUN_CASE(testActualCounterWrap);
    TEST_RUN_CASE(testWrapBoundaryFailure);
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    wCryptoGlobalCleanup();
    return 0;
}
