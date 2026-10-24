/*
 * Covers: VMess AEAD authentication, request/response headers and body framing.
 * Setup: Actual OpenSSL-backed codec, fixed independent Python provider vectors,
 * and V2Fly v5.53.0's published recursive-KDF known answer. No sockets are used.
 * Cases: Reusable AuthID candidate trials, timestamp boundaries, malformed headers,
 * AES/ChaCha/NONE modes, continuous SHAKE padding/masking, authenticated lengths,
 * corrupted EOF tags, full 16-bit lengths, counter exhaustion and raw NONE.
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
            require(
                vmessBodyInit(&rx, vector_key, vector_iv, vector->security, vector->options, vector->command, false) ==
                    kWCryptoOk,
                "vector receiver initialization failed");
            require(
                vmessBodyInit(&tx, vector_key, vector_iv, vector->security, vector->options, vector->command, true) ==
                    kWCryptoOk,
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
        require(vmessBodyInit(&rx, key, iv, records[i].security, records[i].options, 1, false) == kWCryptoOk,
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
        require(vmessBodyInit(&tx, key, iv, records[i].security, records[i].options, 1, true) == kWCryptoOk,
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
    require(vmessBodyInit(&tx, vector_key, vector_iv, 3, 1, 1, true) == kWCryptoOk, "sender init failed");
    tx.counter = UINT16_MAX;
    require(vmessBodySeal(&tx, (const uint8_t *) "x", 1, false, output, sizeof(output), &output_length) ==
                kVmessCounterExhausted,
            "last outgoing nonce used for data");
    require(vmessBodySeal(&tx, NULL, 0, true, output, sizeof(output), &output_length) == kWCryptoOk,
            "reserved outgoing nonce could not seal EOF");
    require(vmessBodyInit(&rx, vector_key, vector_iv, 3, 1, 1, false) == kWCryptoOk, "receiver init failed");
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

    require(vmessBodyInit(&rx, vector_key, vector_iv, 3, 1, 1, false) == kWCryptoOk, "last-frame init failed");
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
        require(vmessBodyInit(&rx, vector_key, vector_iv, security, 29, 1, false) == kWCryptoOk,
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
        require(vmessBodyInit(&tx, vector_key, vector_iv, security, 29, 1, true) == kWCryptoOk,
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
    require(vmessBodyInit(&tx, vector_key, vector_iv, 3, 17, 1, true) == kWCryptoOk, "large sender init failed");
    require(vmessBodyInit(&rx, vector_key, vector_iv, 3, 17, 1, false) == kWCryptoOk, "large receiver init failed");
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

    require(vmessBodyInit(&tx, vector_key, vector_iv, 4, 17, 1, true) == kWCryptoOk, "failure sender init failed");
    require(vmessBodyInit(&rx, vector_key, vector_iv, 4, 17, 1, false) == kWCryptoOk, "failure receiver init failed");
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
    require(vmessBodyInit(&ctx, vector_key, vector_iv, 5, 0, 1, true) == kWCryptoOk && ctx.raw,
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
        require(vmessBodyInit(&ctx, vector_key, vector_iv, bad[i][0], bad[i][1], bad[i][2], false) ==
                    kWCryptoInvalidArgument,
                "unsupported mode/options accepted");
        vmessBodyDestroy(&ctx);
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
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    wCryptoGlobalCleanup();
    return 0;
}
