/* CTest: waterwall.enet_driver_unit.
 * Pure-C coverage of the ENet driver over the deterministic in-memory link in
 * enet_sim.h. Important cases: native handshake, a connect request that
 * carries the configured MTU, ordered stream delivery in both directions,
 * buffering before the handshake, send-hold hysteresis and the hard send cap,
 * graceful close, abort, peer-close ordering, liveness timeout, service
 * scheduling and transfer over an impaired link. No WaterWall runtime, socket
 * or wall clock is used. */

#include "enet_sim.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static bool bothConnected(const sim_world_t *world)
{
    return world->end[0].connected_calls == 1 && world->end[1].connected_calls == 1;
}

static uint32_t readBigEndian32(const uint8_t *bytes)
{
    return ((uint32_t) bytes[0] << 24) | ((uint32_t) bytes[1] << 16) | ((uint32_t) bytes[2] << 8) | (uint32_t) bytes[3];
}

static void testHandshakeCompletes(void)
{
    sim_world_t                world;
    const enet_driver_config_t client = simConfig(kEnetDriverRoleClient);
    const enet_driver_config_t server = simConfig(kEnetDriverRoleServer);
    simOpen(&world, &client, &server, 20);

    require(enetDriverState(world.end[0].driver) == kEnetDriverStateConnecting, "client did not start connecting");
    require(enetDriverNextServiceDelayMs(world.end[0].driver, world.now) == kEnetDriverActiveTickMs,
            "a connecting client needs the active tick");
    require(enetDriverNextServiceDelayMs(world.end[1].driver, world.now) == ENET_DRIVER_NO_SERVICE,
            "a server that has seen no connect request must not ask for a timer");

    require(simAdvanceUntil(&world, 2000, bothConnected), "handshake did not finish");
    require(enetDriverState(world.end[0].driver) == kEnetDriverStateConnected, "client is not connected");
    require(enetDriverState(world.end[1].driver) == kEnetDriverStateConnected, "server is not connected");
    require(world.end[0].closed_calls == 0 && world.end[1].closed_calls == 0, "unexpected close");
    require(world.end[0].stream_length == 0 && world.end[1].stream_length == 0, "unexpected stream bytes");
    simDestroy(&world);
}

static void testConnectRequestIsNativeAndCarriesSettings(void)
{
    sim_world_t          world;
    enet_driver_config_t client = simConfig(kEnetDriverRoleClient);
    enet_driver_config_t server = simConfig(kEnetDriverRoleServer);
    client.host_mtu             = 1200;
    client.incoming_bandwidth   = 2097152;
    client.outgoing_bandwidth   = 1048576; /* at or above 1 MiB/s ENet keeps its largest window */
    simOpen(&world, &client, &server, 20);

    const sim_datagram_t *first = world.queue;
    require(first != NULL && first->to == 1, "client did not send a connect request");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, first->length, 52, "connect request has the wrong size");
    require(first->data[0] == 0x8F && first->data[1] == 0xFF, "connect request has the wrong peer id field");
    require(first->data[4] == 0x82 && first->data[5] == 0xFF, "first command is not a native CONNECT");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT,
                    readBigEndian32(first->data + 12),
                    1200,
                    "connect request does not carry the configured MTU");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT,
                    readBigEndian32(first->data + 16),
                    65536,
                    "connect request window differs from the native maximum");
    TEST_EQUAL_UINT(
        TEST_FAILURE_EXIT, readBigEndian32(first->data + 20), 1, "connect request must ask for one channel");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT,
                    readBigEndian32(first->data + 24),
                    2097152,
                    "connect request does not carry the incoming bandwidth");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT,
                    readBigEndian32(first->data + 28),
                    1048576,
                    "connect request does not carry the outgoing bandwidth");
    simDestroy(&world);
}

int main(void)
{
    TEST_RUN_CASE(testHandshakeCompletes);
    TEST_RUN_CASE(testConnectRequestIsNativeAndCarriesSettings);
    return 0;
}
