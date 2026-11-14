/* CTest: waterwall.enet_native_peer_unit.
 * Runs the driver against a plain ENet host that uses the ENet API directly.
 * Important cases: reliable native packets become stream bytes and the
 * driver's bytes reach the native peer; one channel is negotiated although
 * the native peer asks for two; an unreliable packet is a protocol failure
 * that the native peer is told about; a packet above the receive limit is
 * refused without being delivered. Fixture: a zero-latency wire with virtual
 * time between one driver in the server role and one native client host that
 * runs on the same platform layer. */

#include "EnetCommon/driver.h"
#include "platform.h"

#include "test_assert.h"

#include <stdlib.h>
#include <string.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

enum
{
    kWireDatagramCapacity = 4096
};

typedef struct wire_node_s
{
    struct wire_node_s *next;
    size_t              length;
    uint8_t             data[kWireDatagramCapacity];
} wire_node_t;

typedef struct wire_s
{
    wire_node_t *head;
    wire_node_t *tail;
} wire_t;

typedef struct fixture_s
{
    enet_platform_transport_t native_transport; /* first member: nativeSend casts it back to the fixture */
    uint64_t                  now;
    wire_t                    to_driver;
    wire_t                    to_native;

    enet_driver_t      *driver;
    uint8_t            *stream;
    size_t              stream_length;
    size_t              stream_capacity;
    unsigned            connected_calls;
    unsigned            closed_calls;
    enet_driver_close_t close_reason;

    ENetHost *native_host;
    ENetPeer *native_peer;
    unsigned  native_connects;
    unsigned  native_disconnects;
    size_t    native_received;
} fixture_t;

static wire_node_t *wirePush(wire_t *wire, size_t length)
{
    require(length <= kWireDatagramCapacity, "datagram above the ENet maximum");
    wire_node_t *node = malloc(sizeof(*node));
    require(node != NULL, "out of memory");
    node->next   = NULL;
    node->length = length;
    if (wire->tail != NULL)
    {
        wire->tail->next = node;
    }
    else
    {
        wire->head = node;
    }
    wire->tail = node;
    return node;
}

static wire_node_t *wirePop(wire_t *wire)
{
    wire_node_t *node = wire->head;
    if (node != NULL)
    {
        wire->head = node->next;
        if (wire->head == NULL)
        {
            wire->tail = NULL;
        }
    }
    return node;
}

static bool nativeSend(enet_platform_transport_t *transport, const ENetBuffer *buffers, size_t buffer_count,
                       size_t total_length)
{
    fixture_t   *fixture = (fixture_t *) transport;
    wire_node_t *node    = wirePush(&fixture->to_driver, total_length);
    size_t       offset  = 0;
    for (size_t i = 0; i < buffer_count; ++i)
    {
        memcpy(node->data + offset, buffers[i].data, buffers[i].dataLength);
        offset += buffers[i].dataLength;
    }
    return true;
}

static uint8_t *driverDatagram(void *user, size_t length)
{
    fixture_t *fixture = user;
    return wirePush(&fixture->to_native, length)->data;
}

static void driverStream(void *user, const uint8_t *data, size_t length)
{
    fixture_t *fixture = user;
    if (fixture->stream_length + length > fixture->stream_capacity)
    {
        size_t capacity = fixture->stream_capacity != 0 ? fixture->stream_capacity : 65536;
        while (capacity < fixture->stream_length + length)
        {
            capacity *= 2;
        }
        fixture->stream = realloc(fixture->stream, capacity);
        require(fixture->stream != NULL, "out of memory");
        fixture->stream_capacity = capacity;
    }
    memcpy(fixture->stream + fixture->stream_length, data, length);
    fixture->stream_length += length;
}

static void driverConnected(void *user)
{
    fixture_t *fixture = user;
    fixture->connected_calls += 1;
}

static void driverClosed(void *user, enet_driver_close_t why)
{
    fixture_t *fixture = user;
    fixture->closed_calls += 1;
    fixture->close_reason = why;
}

/* Feeds one datagram (or none) to the native host and collects its events. */
static void nativeService(fixture_t *fixture, const uint8_t *input, size_t length)
{
    fixture->native_transport.now_ms       = (uint32_t) fixture->now;
    fixture->native_transport.input        = input;
    fixture->native_transport.input_length = length;
    enet_platform_transport_t *previous    = enetPlatformEnter(&fixture->native_transport);
    ENetEvent                  event;
    while (enet_host_service(fixture->native_host, &event, 0) > 0)
    {
        switch (event.type)
        {
        case ENET_EVENT_TYPE_CONNECT:
            fixture->native_connects += 1;
            break;
        case ENET_EVENT_TYPE_DISCONNECT:
            fixture->native_disconnects += 1;
            break;
        case ENET_EVENT_TYPE_RECEIVE:
            fixture->native_received += event.packet->dataLength;
            enet_packet_destroy(event.packet);
            break;
        default:
            break;
        }
    }
    enetPlatformLeave(previous);
    fixture->native_transport.input        = NULL;
    fixture->native_transport.input_length = 0;
}

/* One millisecond of virtual time: deliver everything queued in both directions, then tick both ends. */
static void pump(fixture_t *fixture)
{
    for (int round = 0; round < 64 && (fixture->to_driver.head != NULL || fixture->to_native.head != NULL); ++round)
    {
        wire_node_t *node;
        while ((node = wirePop(&fixture->to_driver)) != NULL)
        {
            enetDriverInput(fixture->driver, node->data, node->length, fixture->now);
            free(node);
        }
        while ((node = wirePop(&fixture->to_native)) != NULL)
        {
            nativeService(fixture, node->data, node->length);
            free(node);
        }
    }
    enetDriverService(fixture->driver, fixture->now);
    nativeService(fixture, NULL, 0);
    fixture->now += 1;
}

static void pumpFor(fixture_t *fixture, unsigned milliseconds)
{
    for (unsigned i = 0; i < milliseconds; ++i)
    {
        pump(fixture);
    }
}

static void fixtureOpen(fixture_t *fixture, uint32_t receive_buffer_limit)
{
    static const enet_driver_sinks_t sinks = {
        .datagram = driverDatagram, .stream = driverStream, .connected = driverConnected, .closed = driverClosed};
    const enet_driver_config_t config = {
        .role                 = kEnetDriverRoleServer,
        .host_mtu             = 1472,
        .ping_interval_ms     = 200,
        .no_recv_timeout_ms   = 500,
        .send_buffer_limit    = 524288,
        .receive_buffer_limit = receive_buffer_limit,
        .incoming_bandwidth   = 0,
        .outgoing_bandwidth   = 0,
        .random_seed          = 11,
    };

    require(enetDriverInstall(malloc, free), "allocator install failed");
    memset(fixture, 0, sizeof(*fixture));
    fixture->now    = 1000;
    fixture->driver = enetDriverCreate(&config, &sinks, fixture, fixture->now);
    require(fixture->driver != NULL, "driver creation failed");

    fixture->native_transport.send        = nativeSend;
    fixture->native_transport.random_seed = 22;
    fixture->native_transport.now_ms      = (uint32_t) fixture->now;
    enet_platform_transport_t *previous   = enetPlatformEnter(&fixture->native_transport);
    /* A native application that asks for two channels, as the ENet tutorial does. */
    fixture->native_host = enet_host_create(NULL, 1, 2, 0, 0);
    require(fixture->native_host != NULL, "native host creation failed");
    ENetAddress address;
    address.host         = kEnetPlatformPeerHost;
    address.port         = kEnetPlatformPeerPort;
    fixture->native_peer = enet_host_connect(fixture->native_host, &address, 2, 0);
    require(fixture->native_peer != NULL, "native connect could not be queued");
    enetPlatformLeave(previous);

    for (int i = 0; i < 500 && (fixture->native_connects == 0 || fixture->connected_calls == 0); ++i)
    {
        pump(fixture);
    }
    require(fixture->native_connects == 1 && fixture->connected_calls == 1, "native handshake failed");
    require(fixture->native_peer->channelCount == 1, "the driver must negotiate exactly one channel");
}

static void fixtureClose(fixture_t *fixture)
{
    enet_platform_transport_t *previous = enetPlatformEnter(&fixture->native_transport);
    enet_host_destroy(fixture->native_host);
    enetPlatformLeave(previous);
    enetDriverDestroy(fixture->driver);
    free(fixture->stream);
    wire_node_t *node;
    while ((node = wirePop(&fixture->to_driver)) != NULL)
    {
        free(node);
    }
    while ((node = wirePop(&fixture->to_native)) != NULL)
    {
        free(node);
    }
}

static void nativeSendPacket(fixture_t *fixture, const uint8_t *data, size_t length, enet_uint32 flags)
{
    fixture->native_transport.now_ms    = (uint32_t) fixture->now;
    enet_platform_transport_t *previous = enetPlatformEnter(&fixture->native_transport);
    ENetPacket                *packet   = enet_packet_create(data, length, flags);
    require(packet != NULL && enet_peer_send(fixture->native_peer, 0, packet) == 0,
            "native peer could not queue a packet");
    enetPlatformLeave(previous);
}

static uint8_t *pattern(size_t length, uint32_t seed)
{
    uint8_t *bytes = malloc(length != 0 ? length : 1);
    require(bytes != NULL, "out of memory");
    uint32_t state = seed;
    for (size_t i = 0; i < length; ++i)
    {
        state    = state * 1664525U + 1013904223U;
        bytes[i] = (uint8_t) (state >> 24);
    }
    return bytes;
}

static void testNativeReliablePacketsBecomeStreamBytes(void)
{
    fixture_t fixture;
    fixtureOpen(&fixture, 1048576);

    uint8_t *up = pattern(3000, 1);
    nativeSendPacket(&fixture, up, 3000, ENET_PACKET_FLAG_RELIABLE);
    pumpFor(&fixture, 100);
    TEST_EQUAL_SIZE(
        TEST_FAILURE_EXIT, fixture.stream_length, 3000, "a native reliable packet was not delivered as stream bytes");
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, fixture.stream, up, 3000, "delivered bytes differ");

    uint8_t *down = pattern(5000, 2);
    require(enetDriverWrite(fixture.driver, down, 5000, fixture.now), "driver write refused");
    pumpFor(&fixture, 100);
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, fixture.native_received, 5000, "native peer did not receive the driver's bytes");
    require(fixture.closed_calls == 0 && fixture.native_disconnects == 0, "session ended during a plain exchange");

    free(up);
    free(down);
    fixtureClose(&fixture);
}

static void testUnreliablePacketIsAProtocolFailure(void)
{
    static const uint8_t bytes[10] = {0};
    fixture_t            fixture;
    fixtureOpen(&fixture, 1048576);

    nativeSendPacket(&fixture, bytes, sizeof(bytes), 0);
    pumpFor(&fixture, 100);
    require(fixture.closed_calls == 1 && fixture.close_reason == kEnetDriverCloseProtocol,
            "an unreliable packet must end the session with a protocol failure");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, fixture.stream_length, 0, "an unreliable packet must not reach the stream");
    require(fixture.native_disconnects == 1, "the native peer must be told about the failure");

    fixtureClose(&fixture);
}

static void testOversizedPacketIsRefused(void)
{
    fixture_t fixture;
    fixtureOpen(&fixture, 131072); /* the driver then accepts native messages of at most 65536 bytes */
    enet_peer_timeout(fixture.native_peer, 0, 500, 500);

    uint8_t *big = pattern(100000, 3);
    nativeSendPacket(&fixture, big, 100000, ENET_PACKET_FLAG_RELIABLE);
    pumpFor(&fixture, 4000);
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, fixture.stream_length, 0, "an oversized packet must not be delivered");
    require(fixture.native_disconnects == 1, "the native sender must time out when its packet is never acknowledged");
    require(fixture.closed_calls == 1 && fixture.close_reason == kEnetDriverCloseRemote,
            "the driver must notice that the native peer went away");

    free(big);
    fixtureClose(&fixture);
}

int main(void)
{
    TEST_RUN_CASE(testNativeReliablePacketsBecomeStreamBytes);
    TEST_RUN_CASE(testUnreliablePacketIsAProtocolFailure);
    TEST_RUN_CASE(testOversizedPacketIsRefused);
    return 0;
}
