#include "test_assert.h"
#include "ww-rtmp-engine.h"

#include <errno.h>
#include <string.h>

enum
{
    kClient,
    kServer,
    kPeerCount,
    kHandshakeSize = 1536,
    kAckThreshold  = kRtmpInitialAckWindow / 2,
};

typedef struct
{
    ww_rtmp_engine_t *engine;
    uint8_t           wire[2 * kAckThreshold];
    size_t            wire_length;
    size_t            received;
    size_t            data_messages;
    uint32_t          stream_id;
    ww_rtmp_output_e  output_kind;
    bool              publish;
    bool              ready;
    bool              refuse_output;
} engine_peer_t;

static int captureOutput(void *context, const void *header, size_t header_size, const void *payload,
                         size_t payload_size, ww_rtmp_output_e kind)
{
    engine_peer_t *peer = context;
    peer->output_kind   = kind;
    if (peer->refuse_output)
        return -1;

    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 header_size + payload_size <= sizeof(peer->wire) - peer->wire_length,
                 "engine fixture exceeded capture capacity");
    if (header_size)
        memcpy(peer->wire + peer->wire_length, header, header_size);
    if (payload_size)
        memcpy(peer->wire + peer->wire_length + header_size, payload, payload_size);
    peer->wire_length += header_size + payload_size;
    return 0;
}

static int captureData(void *context, const void *body, size_t size, uint32_t timestamp, uint32_t chunk_stream,
                       uint32_t message_stream)
{
    engine_peer_t *peer = context;
    (void) body;
    (void) size;
    (void) timestamp;
    (void) chunk_stream;
    (void) message_stream;
    ++peer->data_messages;
    return 0;
}

static int captureEvent(void *context, ww_rtmp_event_e event, uint32_t value, uint8_t detail)
{
    engine_peer_t *peer = context;
    (void) detail;
    if (event == kRtmpEventPublish)
        peer->publish = true;
    if (event == kRtmpEventReady)
    {
        peer->ready     = true;
        peer->stream_id = value;
    }
    return 0;
}

static int countInput(void *context, size_t size)
{
    engine_peer_t *peer = context;
    peer->received += size;
    return 0;
}

static const ww_rtmp_engine_callbacks_t callbacks = {
    .send = captureOutput, .data = captureData, .event = captureEvent, .received = countInput};

static void openPair(engine_peer_t peers[kPeerCount])
{
    peers[kClient].engine =
        wwRtmpEngineCreate(false, "waterwall", "tunnel", "rtmp://localhost/waterwall", &callbacks, &peers[kClient]);
    peers[kServer].engine = wwRtmpEngineCreate(true, "waterwall", "tunnel", NULL, &callbacks, &peers[kServer]);
    TEST_REQUIRE(TEST_FAILURE_EXIT, peers[kClient].engine && peers[kServer].engine, "create RTMP engines");
    TEST_REQUIRE(TEST_FAILURE_EXIT, wwRtmpEngineStart(peers[kClient].engine) == 0, "start client engine");

    for (unsigned turn = 0; turn < 16 && (peers[kClient].wire_length || peers[kServer].wire_length); ++turn)
    {
        for (size_t from = 0; from < kPeerCount; ++from)
        {
            engine_peer_t *sender   = &peers[from];
            engine_peer_t *receiver = &peers[from ^ 1U];
            TEST_REQUIRE(TEST_FAILURE_EXIT,
                         wwRtmpEngineInput(receiver->engine, sender->wire, sender->wire_length) == 0,
                         "forward setup bytes");
            sender->wire_length = 0;
            if (receiver->publish)
            {
                receiver->publish = false;
                TEST_REQUIRE(TEST_FAILURE_EXIT, wwRtmpEngineAccept(receiver->engine) == 0, "accept publication");
            }
        }
    }
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 peers[kClient].ready && peers[kServer].ready && peers[kClient].wire_length == 0 &&
                     peers[kServer].wire_length == 0,
                 "settle RTMP setup");
}

static void closePair(engine_peer_t peers[kPeerCount])
{
    for (size_t i = 0; i < kPeerCount; ++i)
        wwRtmpEngineDestroy(peers[i].engine);
}

static void handshakeServer(engine_peer_t *server)
{
    uint8_t request[1 + kHandshakeSize] = {3, 0, 0, 0, 1};
    for (size_t i = 9; i < sizeof(request); ++i)
        request[i] = (uint8_t) i;

    server->engine = wwRtmpEngineCreate(true, "waterwall", "tunnel", NULL, &callbacks, server);
    TEST_REQUIRE(TEST_FAILURE_EXIT, server->engine != NULL, "create server engine");
    TEST_EQUAL_INT(TEST_FAILURE_EXIT, wwRtmpEngineInput(server->engine, request, sizeof(request)), 0, "receive C0/C1");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, server->wire_length, 1 + 2 * kHandshakeSize, "S0/S1/S2 size");
    const uint8_t *s1 = server->wire + 1;
    const uint8_t *s2 = s1 + kHandshakeSize;
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, s2, request + 1, 4, "S2 echoes the C1 timestamp");
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, s2 + 4, s1, 4, "S2 contains the server's C1 receive timestamp");
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, s2 + 8, request + 9, kHandshakeSize - 8, "S2 echoes the C1 random data");

    uint8_t reply[kHandshakeSize];
    memcpy(reply, s1, sizeof(reply));
    reply[7]            = 2; /* Client receive time in C2. */
    server->wire_length = 0;
    TEST_EQUAL_INT(TEST_FAILURE_EXIT, wwRtmpEngineInput(server->engine, reply, sizeof(reply)), 0, "receive C2");
}

static void testConnectObjectTerminator(void)
{
    /* A single AMF0 connect command, through the final property value. */
    static const uint8_t fields[] = "\x02\0\x07"
                                    "connect"
                                    "\0\x3f\xf0\0\0\0\0\0\0"
                                    "\x03\0\x03"
                                    "app"
                                    "\x02\0\x09"
                                    "waterwall"
                                    "\0\x05"
                                    "tcUrl"
                                    "\x02\0\x14"
                                    "rtmp://h/waterwall/a"
                                    "\0\x0e"
                                    "objectEncoding"
                                    "\0\x40\x08\0\0\0\0\0\0";
    static const uint8_t end[]    = {0, 0, 9};
    enum
    {
        kHeaderSize = 12,
        kFieldsSize = sizeof(fields) - 1
    };
    for (size_t omitted = 0; omitted <= 2; ++omitted)
    {
        engine_peer_t server = {0};
        handshakeServer(&server);
        const size_t body_size                                      = kFieldsSize + sizeof(end) - omitted;
        uint8_t      chunk[kHeaderSize + kFieldsSize + sizeof(end)] = {3, 0, 0, 0, 0, 0, (uint8_t) body_size, 20};
        memcpy(chunk + kHeaderSize, fields, kFieldsSize);
        memcpy(chunk + kHeaderSize + kFieldsSize, end + omitted, sizeof(end) - omitted);
        const int result = wwRtmpEngineInput(server.engine, chunk, kHeaderSize + body_size);
        TEST_EQUAL_INT(TEST_FAILURE_EXIT, result, omitted == 0 ? 0 : -EINVAL, "connect requires a complete object end");
        TEST_REQUIRE(
            TEST_FAILURE_EXIT, (server.wire_length > 0) == (omitted == 0), "only a valid connect gets a reply");
        wwRtmpEngineDestroy(server.engine);
    }
}

static void testPingAndOutputRefusal(void)
{
    /* CSID 2, user control type 4, Ping Request/Response, timestamp 0x81112233. */
    static const uint8_t ping[]            = {2, 0, 0, 0, 0, 0, 6, 4, 0, 0, 0, 0, 0, 6, 0x81, 0x11, 0x22, 0x33};
    static const uint8_t pong[]            = {2, 0, 0, 0, 0, 0, 6, 4, 0, 0, 0, 0, 0, 7, 0x81, 0x11, 0x22, 0x33};
    engine_peer_t        peers[kPeerCount] = {0};
    openPair(peers);
    for (size_t i = 0; i < kPeerCount; ++i)
    {
        engine_peer_t *peer = &peers[i];
        TEST_REQUIRE(
            TEST_FAILURE_EXIT, wwRtmpEngineInput(peer->engine, ping, sizeof(ping)) == 0, "process Ping Request");
        TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, peer->wire_length, sizeof(pong), "Ping Response size");
        TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, peer->wire, pong, sizeof(pong), "Ping Response preserves timestamp");
        TEST_EQUAL_UINT(TEST_FAILURE_EXIT, peer->output_kind, kRtmpOutputUrgent, "Ping Response priority");

        peer->wire_length   = 0;
        peer->refuse_output = true;
        TEST_EQUAL_INT(TEST_FAILURE_EXIT,
                       wwRtmpEngineInput(peer->engine, ping, sizeof(ping)),
                       -1,
                       "input swallowed refused Ping Response");
        TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, peer->wire_length, 0, "refused output was captured");
    }
    closePair(peers);
}

static void testEarlyAckAndAbort(void)
{
    /* A valid 16-KiB ww.data ByteArray, followed separately by a CSID 6 Abort. */
    static const uint8_t body[16384 + 16] = {
        0, 2, 0, 7, 'w', 'w', '.', 'd', 'a', 't', 'a', 0x11, 0x0c, 0x82, 0x80, 0x01};
    static const uint8_t ack[]             = {2, 0, 0, 0, 0, 0, 4, 3, 0, 0, 0, 0, 0, 0, 0x40, 0};
    static const uint8_t abort_message[]   = {2, 0, 0, 0, 0, 0, 4, 2, 0, 0, 0, 0, 0, 0, 0, 6};
    engine_peer_t        peers[kPeerCount] = {0};
    openPair(peers);

    engine_peer_t *sender   = &peers[kClient];
    engine_peer_t *receiver = &peers[kServer];
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 receiver->received > 0 && receiver->received < kAckThreshold - 1,
                 "setup bytes must be below the first ACK threshold");
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 wwRtmpEngineSendData(sender->engine, body, sizeof(body), 0) == 0,
                 "serialize the test data message");
    const size_t remaining = kAckThreshold - receiver->received;
    TEST_REQUIRE(TEST_FAILURE_EXIT, sender->wire_length > remaining, "test input must stop inside a message");
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 wwRtmpEngineInput(receiver->engine, sender->wire, remaining - 1) == 0,
                 "receive bytes below the ACK threshold");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, receiver->wire_length, 0, "generated premature ACK");
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 wwRtmpEngineInput(receiver->engine, sender->wire + remaining - 1, 1) == 0,
                 "receive the last byte up to the ACK threshold");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, receiver->wire_length, sizeof(ack), "exact-threshold ACK size");
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, receiver->wire, ack, sizeof(ack), "exact-threshold ACK sequence");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, receiver->output_kind, kRtmpOutputUrgent, "ACK priority");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, receiver->data_messages, 0, "delivered an incomplete data message");

    /* Four complete chunks use a 12-byte initial header and three 1-byte continuation headers. */
    const size_t first_chunks = 12 + kRtmpOutChunkSize + 3 * (1 + kRtmpOutChunkSize);
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 remaining < first_chunks && first_chunks < sender->wire_length,
                 "test must retain a partial data message at the chunk boundary");
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 wwRtmpEngineInput(receiver->engine, sender->wire + remaining, first_chunks - remaining) == 0,
                 "receive the rest of the chunk");
    TEST_EQUAL_INT(TEST_FAILURE_EXIT,
                   wwRtmpEngineInput(receiver->engine, abort_message, sizeof(abort_message)),
                   -ECANCELED,
                   "Abort of a partial application message must fail the stream");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, receiver->data_messages, 0, "Abort delivered truncated application data");
    closePair(peers);
}

static void rejectDataHeader(uint8_t chunk_stream, uint32_t stream_offset, uint32_t length)
{
    engine_peer_t peers[kPeerCount] = {0};
    openPair(peers);
    engine_peer_t *peer      = &peers[kServer];
    const uint32_t stream_id = peer->stream_id + stream_offset;
    const uint8_t  header[]  = {chunk_stream,
                                0,
                                0,
                                0,
                                (uint8_t) (length >> 16U),
                                (uint8_t) (length >> 8U),
                                (uint8_t) length,
                                15,
                                (uint8_t) stream_id,
                                (uint8_t) (stream_id >> 8U),
                                (uint8_t) (stream_id >> 16U),
                                (uint8_t) (stream_id >> 24U)};
    TEST_EQUAL_INT(TEST_FAILURE_EXIT,
                   wwRtmpEngineInput(peer->engine, header, sizeof(header)),
                   -EINVAL,
                   "refuse invalid type-15 routing or size before parsing the body");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, peer->data_messages, 0, "invalid header dispatched application data");
    closePair(peers);
}

static void testDataHeaderAdmission(void)
{
    rejectDataHeader(kRtmpDataChunkStream, 0, kRtmpMaxMessageSize + 1);
    rejectDataHeader(kRtmpDataChunkStream, 1, 16);
    rejectDataHeader(kRtmpDataChunkStream + 1, 0, 16);
}

int main(void)
{
    TEST_RUN_CASE(testConnectObjectTerminator);
    TEST_RUN_CASE(testPingAndOutputRefusal);
    TEST_RUN_CASE(testEarlyAckAndAbort);
    TEST_RUN_CASE(testDataHeaderAdmission);
    return 0;
}
