/* CTest: waterwall.enet_platform_unit.
 * Covers the WaterWall replacement for ENet's unix.c/win32.c. Important cases:
 * a host is created, connected and destroyed without any OS socket; the
 * connect request reaches the active transport as one native datagram that
 * carries the host MTU; a fed datagram is consumed exactly once; oversized
 * input is skipped; a refused send counts as a drop; time and seed come from
 * the transport. Fixture: one transport that records what ENet sends. */

#include "platform.h"

#include "test_assert.h"

#include <stdlib.h>
#include <string.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

typedef struct recording_transport_s
{
    enet_platform_transport_t transport; /* first member */
    unsigned                  sends;
    size_t                    last_length;
    uint8_t                   last[4096];
    bool                      refuse;
} recording_transport_t;

static bool recordSend(enet_platform_transport_t *transport, const ENetBuffer *buffers, size_t buffer_count,
                       size_t total_length)
{
    recording_transport_t *recorder = (recording_transport_t *) transport;
    recorder->sends += 1;
    if (recorder->refuse)
    {
        return false;
    }
    require(total_length <= sizeof(recorder->last), "ENet produced a datagram above its own maximum");
    size_t offset = 0;
    for (size_t i = 0; i < buffer_count; ++i)
    {
        memcpy(recorder->last + offset, buffers[i].data, buffers[i].dataLength);
        offset += buffers[i].dataLength;
    }
    require(offset == total_length, "gathered length disagrees with the reported total");
    recorder->last_length = total_length;
    return true;
}

static void *ENET_CALLBACK testAllocate(size_t size)
{
    return malloc(size);
}

static void ENET_CALLBACK testRelease(void *memory)
{
    free(memory);
}

static void recorderInit(recording_transport_t *recorder, uint32_t now_ms, uint32_t seed)
{
    memset(recorder, 0, sizeof(*recorder));
    recorder->transport.send        = recordSend;
    recorder->transport.now_ms      = now_ms;
    recorder->transport.random_seed = seed;
}

static uint32_t readBigEndian32(const uint8_t *bytes)
{
    return ((uint32_t) bytes[0] << 24) | ((uint32_t) bytes[1] << 16) | ((uint32_t) bytes[2] << 8) | (uint32_t) bytes[3];
}

/* The platform ignores the socket argument; any non-null value stands in for it. */
static ENetSocket placeholderSocket(void)
{
    return enet_socket_create(ENET_SOCKET_TYPE_DATAGRAM);
}

static void testInstallIsIdempotent(void)
{
    require(enetPlatformInstall(testAllocate, testRelease), "first install failed");
    require(enetPlatformInstall(testAllocate, testRelease), "second install must succeed without changes");
}

static void testEnterAndLeaveNest(void)
{
    recording_transport_t outer;
    recording_transport_t inner;
    recorderInit(&outer, 1000, 1);
    recorderInit(&inner, 1000, 2);

    enet_platform_transport_t *before_outer = enetPlatformEnter(&outer.transport);
    require(before_outer == NULL, "no transport should be active before the first enter");
    enet_platform_transport_t *before_inner = enetPlatformEnter(&inner.transport);
    require(before_inner == &outer.transport, "enter must return the previously active transport");
    require(enet_host_random_seed() == 2, "platform calls must use the innermost transport");
    enetPlatformLeave(before_inner);
    require(enet_host_random_seed() == 1, "leave must restore the outer transport");
    enetPlatformLeave(before_outer);
}

static void testTimeAndSeedComeFromTransport(void)
{
    recording_transport_t recorder;
    recorderInit(&recorder, 123456, 77);
    enet_platform_transport_t *previous = enetPlatformEnter(&recorder.transport);
    require(enet_time_get() == 123456, "time must come from the active transport");
    require(enet_host_random_seed() == 77, "seed must come from the active transport");
    recorder.transport.now_ms = 0;
    require(enet_time_get() == 1, "ENet treats zero as unset, so zero time must be reported as one");
    enetPlatformLeave(previous);
}

static void testHostLifecycleAndNativeConnectRequest(void)
{
    recording_transport_t recorder;
    recorderInit(&recorder, 1000, 5);
    enet_platform_transport_t *previous = enetPlatformEnter(&recorder.transport);

    ENetHost *host = enet_host_create(NULL, 1, 1, 0, 0);
    require(host != NULL, "host creation failed without a socket");
    require(host->socket != ENET_SOCKET_NULL, "host must hold a non-null placeholder socket");
    host->mtu = 1200;

    ENetAddress address;
    address.host   = kEnetPlatformPeerHost;
    address.port   = kEnetPlatformPeerPort;
    ENetPeer *peer = enet_host_connect(host, &address, 1, 0);
    require(peer != NULL, "connect request could not be queued");

    ENetEvent event;
    require(enet_host_service(host, &event, 0) == 0, "zero-timeout service must return without an event");
    require(recorder.sends == 1, "the connect request must be sent as exactly one datagram");
    /* ENet header: peer id 0xFFF with the sent-time flag. Then a CONNECT command with the acknowledge flag. */
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, recorder.last_length, 52, "connect request has the wrong size");
    require(recorder.last[0] == 0x8F && recorder.last[1] == 0xFF, "connect request has the wrong peer id field");
    require(recorder.last[4] == 0x82 && recorder.last[5] == 0xFF, "first command is not a native CONNECT");
    TEST_EQUAL_UINT(
        TEST_FAILURE_EXIT, readBigEndian32(recorder.last + 12), 1200, "connect request does not carry the host MTU");
    TEST_EQUAL_UINT(
        TEST_FAILURE_EXIT, readBigEndian32(recorder.last + 20), 1, "connect request must ask for one channel");

    enet_host_destroy(host);
    enetPlatformLeave(previous);
}

static void testInputIsConsumedOnce(void)
{
    static const uint8_t  datagram[5] = {1, 2, 3, 4, 5};
    recording_transport_t recorder;
    recorderInit(&recorder, 1000, 5);
    enet_platform_transport_t *previous = enetPlatformEnter(&recorder.transport);

    uint8_t     storage[64];
    ENetBuffer  buffer;
    ENetAddress from;
    buffer.data       = storage;
    buffer.dataLength = sizeof(storage);
    memset(&from, 0, sizeof(from));

    recorder.transport.input        = datagram;
    recorder.transport.input_length = sizeof(datagram);
    require(enet_socket_receive(placeholderSocket(), &from, &buffer, 1) == 5, "datagram was not delivered");
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, storage, datagram, sizeof(datagram), "delivered bytes differ");
    require(from.host == kEnetPlatformPeerHost && from.port == kEnetPlatformPeerPort,
            "received address must be the fixed synthetic peer");
    require(enet_socket_receive(placeholderSocket(), &from, &buffer, 1) == 0,
            "a datagram must be delivered exactly once");

    enetPlatformLeave(previous);
}

static void testOversizedInputIsSkipped(void)
{
    static const uint8_t  datagram[5] = {1, 2, 3, 4, 5};
    recording_transport_t recorder;
    recorderInit(&recorder, 1000, 5);
    enet_platform_transport_t *previous = enetPlatformEnter(&recorder.transport);

    uint8_t    storage[4];
    ENetBuffer buffer;
    buffer.data       = storage;
    buffer.dataLength = sizeof(storage);

    recorder.transport.input        = datagram;
    recorder.transport.input_length = sizeof(datagram);
    require(enet_socket_receive(placeholderSocket(), NULL, &buffer, 1) == -2,
            "a datagram larger than the buffer must be reported as truncated");
    require(enet_socket_receive(placeholderSocket(), NULL, &buffer, 1) == 0,
            "a skipped datagram must not be offered again");

    enetPlatformLeave(previous);
}

static void testRefusedSendCountsAsDrop(void)
{
    static uint8_t        bytes[5] = {9, 9, 9, 9, 9};
    recording_transport_t recorder;
    recorderInit(&recorder, 1000, 5);
    recorder.refuse                     = true;
    enet_platform_transport_t *previous = enetPlatformEnter(&recorder.transport);

    ENetBuffer buffer;
    buffer.data       = bytes;
    buffer.dataLength = sizeof(bytes);
    require(enet_socket_send(placeholderSocket(), NULL, &buffer, 1) == 5,
            "a refused datagram must still be reported as sent so ENet treats it as loss");
    require(recorder.transport.dropped == 1, "a refused datagram must be counted");

    enetPlatformLeave(previous);
}

int main(void)
{
    TEST_RUN_CASE(testInstallIsIdempotent);
    TEST_RUN_CASE(testEnterAndLeaveNest);
    TEST_RUN_CASE(testTimeAndSeedComeFromTransport);
    TEST_RUN_CASE(testHostLifecycleAndNativeConnectRequest);
    TEST_RUN_CASE(testInputIsConsumedOnce);
    TEST_RUN_CASE(testOversizedInputIsSkipped);
    TEST_RUN_CASE(testRefusedSendCountsAsDrop);
    return 0;
}
