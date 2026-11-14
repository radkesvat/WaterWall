/* CTest: waterwall.enet_driver_unit.
 * Pure-C coverage of the ENet driver over the deterministic in-memory link in
 * enet_sim.h. Important cases: native handshake, a connect request that
 * carries the configured MTU, ordered stream delivery in both directions,
 * buffering before the handshake, send-hold hysteresis and the hard send cap,
 * graceful close, abort, peer-close ordering, liveness timeout, service
 * scheduling, transfer over an impaired link, and a lost command that meets
 * the receive limit. No WaterWall runtime, socket or wall clock is used. */

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

static size_t expected_bytes[2];

static bool expectedBytesArrived(const sim_world_t *world)
{
    return world->end[0].stream_length >= expected_bytes[0] && world->end[1].stream_length >= expected_bytes[1];
}

static void openConnected(sim_world_t *world, const enet_driver_config_t *client, const enet_driver_config_t *server,
                          uint32_t delay_ms)
{
    simOpen(world, client, server, delay_ms);
    require(simAdvanceUntil(world, 2000, bothConnected), "handshake did not finish");
}

static bool bothClosed(const sim_world_t *world)
{
    return world->end[0].closed_calls == 1 && world->end[1].closed_calls == 1;
}

static bool serverClosed(const sim_world_t *world)
{
    return world->end[1].closed_calls == 1;
}

static void closeEnd(sim_world_t *world, int index)
{
    enetDriverClose(world->end[index].driver, world->now);
    simSchedule(&world->end[index]);
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

static void testStreamRoundTripInOrder(void)
{
    static const size_t        sizes[] = {1, 1000, 65536, 65537, 200000};
    sim_world_t                world;
    const enet_driver_config_t client = simConfig(kEnetDriverRoleClient);
    const enet_driver_config_t server = simConfig(kEnetDriverRoleServer);
    openConnected(&world, &client, &server, 20);

    size_t total = 0;
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i)
    {
        total += sizes[i];
    }
    uint8_t *up     = simPattern(total, 1);
    uint8_t *down   = simPattern(total, 2);
    size_t   offset = 0;
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i)
    {
        require(simWrite(&world, 0, up + offset, sizes[i]), "client write refused");
        require(simWrite(&world, 1, down + offset, sizes[i]), "server write refused");
        offset += sizes[i];
    }

    expected_bytes[0] = total;
    expected_bytes[1] = total;
    require(simAdvanceUntil(&world, 60000, expectedBytesArrived), "stream bytes did not arrive");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, world.end[1].stream_length, total, "server received a different length");
    TEST_EQUAL_BYTES(
        TEST_FAILURE_EXIT, world.end[1].stream, up, total, "server stream differs from the client's bytes");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, world.end[0].stream_length, total, "client received a different length");
    TEST_EQUAL_BYTES(
        TEST_FAILURE_EXIT, world.end[0].stream, down, total, "client stream differs from the server's bytes");

    simAdvance(&world, 500);
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, enetDriverQueuedBytes(world.end[0].driver), 0, "client bytes stayed queued");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, enetDriverQueuedBytes(world.end[1].driver), 0, "server bytes stayed queued");
    require(world.end[0].closed_calls == 0 && world.end[1].closed_calls == 0, "session closed during transfer");

    free(up);
    free(down);
    simDestroy(&world);
}

static void testWriteBeforeHandshakeIsDelivered(void)
{
    sim_world_t                world;
    const enet_driver_config_t client = simConfig(kEnetDriverRoleClient);
    const enet_driver_config_t server = simConfig(kEnetDriverRoleServer);
    simOpen(&world, &client, &server, 20);

    uint8_t *up   = simPattern(150000, 3);
    uint8_t *down = simPattern(70000, 4);
    require(simWrite(&world, 0, up, 150000), "client write before the handshake was refused");
    require(simWrite(&world, 1, down, 70000), "server write before the handshake was refused");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT,
                    enetDriverQueuedBytes(world.end[0].driver),
                    150000,
                    "bytes buffered before the handshake are not counted");
    require(enetDriverState(world.end[0].driver) == kEnetDriverStateConnecting, "client connected too early");

    expected_bytes[0] = 70000;
    expected_bytes[1] = 150000;
    require(simAdvanceUntil(&world, 60000, expectedBytesArrived), "buffered bytes did not arrive");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, world.end[1].stream_length, 150000, "server received a different length");
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, world.end[1].stream, up, 150000, "server stream differs");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, world.end[0].stream_length, 70000, "client received a different length");
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, world.end[0].stream, down, 70000, "client stream differs");

    free(up);
    free(down);
    simDestroy(&world);
}

static void testSendHoldHysteresisAndHardCap(void)
{
    sim_world_t          world;
    enet_driver_config_t client = simConfig(kEnetDriverRoleClient);
    enet_driver_config_t server = simConfig(kEnetDriverRoleServer);
    client.send_buffer_limit    = 8192;
    openConnected(&world, &client, &server, 20);
    enet_driver_t *driver = world.end[0].driver;
    uint8_t       *bytes  = simPattern(9000, 5);

    world.cut = true; /* nothing is acknowledged while the link is cut */
    require(simWrite(&world, 0, bytes, 8192), "write up to the limit was refused");
    require(! enetDriverSendHold(driver), "reaching the limit exactly must not start the hold");
    require(simWrite(&world, 0, bytes, 1), "write above the limit was refused");
    require(enetDriverSendHold(driver), "exceeding the limit must start the hold");
    require(simWrite(&world, 0, bytes, 8000), "write below the hard cap was refused");
    require(simWrite(&world, 0, bytes, 9000), "a payload offered below the hard cap must be admitted whole");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, enetDriverQueuedBytes(driver), 25193, "queued byte count is wrong");
    require(! enetDriverWrite(driver, bytes, 1, world.now), "a payload offered above the hard cap must be refused");
    require(enetDriverState(driver) == kEnetDriverStateConnected, "a refused payload must not close the driver");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, enetDriverQueuedBytes(driver), 25193, "a refused payload changed the queue");

    world.cut               = false;
    const uint64_t deadline = world.now + 60000;
    while (enetDriverQueuedBytes(driver) > 0)
    {
        require(world.now < deadline, "queued bytes were never acknowledged");
        simStep(&world);
        if (enetDriverQueuedBytes(driver) > 4096)
        {
            require(enetDriverSendHold(driver), "the hold was released above half of the limit");
        }
    }
    require(! enetDriverSendHold(driver), "the hold was not released after the queue drained");
    require(world.end[0].closed_calls == 0, "session closed while draining");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, world.end[1].stream_length, 25193, "server did not receive every accepted byte");

    free(bytes);
    simDestroy(&world);
}

static void testGracefulCloseDeliversEverything(void)
{
    sim_world_t                world;
    const enet_driver_config_t client = simConfig(kEnetDriverRoleClient);
    const enet_driver_config_t server = simConfig(kEnetDriverRoleServer);
    openConnected(&world, &client, &server, 20);

    uint8_t *bytes = simPattern(300000, 6);
    require(simWrite(&world, 0, bytes, 300000), "write refused");
    closeEnd(&world, 0);
    require(enetDriverState(world.end[0].driver) == kEnetDriverStateClosing, "client did not enter the closing state");
    require(world.end[0].closed_calls == 0, "close must not finish before the bytes are delivered");

    require(simAdvanceUntil(&world, 60000, bothClosed), "graceful close did not finish");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, world.end[1].stream_length, 300000, "server did not receive every byte");
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, world.end[1].stream, bytes, 300000, "server stream differs");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT,
                    world.end[1].stream_length_at_close,
                    300000,
                    "server was told about the close before the last bytes");
    require(world.end[0].close_reason == kEnetDriverCloseLocal, "client must report a local close");
    require(world.end[1].close_reason == kEnetDriverCloseRemote, "server must report a remote close");
    require(enetDriverState(world.end[0].driver) == kEnetDriverStateClosed, "client is not closed");
    require(enetDriverState(world.end[1].driver) == kEnetDriverStateClosed, "server is not closed");

    free(bytes);
    simDestroy(&world);
}

static void testCloseBeforeHandshakeStillDelivers(void)
{
    sim_world_t                world;
    const enet_driver_config_t client = simConfig(kEnetDriverRoleClient);
    const enet_driver_config_t server = simConfig(kEnetDriverRoleServer);
    simOpen(&world, &client, &server, 20);

    uint8_t *bytes = simPattern(50000, 7);
    require(simWrite(&world, 0, bytes, 50000), "write before the handshake was refused");
    closeEnd(&world, 0);
    require(enetDriverState(world.end[0].driver) == kEnetDriverStateConnecting,
            "a close with buffered bytes must wait for the handshake");

    require(simAdvanceUntil(&world, 60000, bothClosed), "close did not finish");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, world.end[1].stream_length, 50000, "server did not receive the buffered bytes");
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, world.end[1].stream, bytes, 50000, "server stream differs");
    require(world.end[0].close_reason == kEnetDriverCloseLocal, "client must report a local close");
    require(world.end[1].close_reason == kEnetDriverCloseRemote, "server must report a remote close");

    free(bytes);
    simDestroy(&world);
}

static void testCloseBeforeHandshakeWithoutBytesEndsNow(void)
{
    sim_world_t                world;
    const enet_driver_config_t client = simConfig(kEnetDriverRoleClient);
    const enet_driver_config_t server = simConfig(kEnetDriverRoleServer);
    simOpen(&world, &client, &server, 20);

    closeEnd(&world, 0);
    require(enetDriverState(world.end[0].driver) == kEnetDriverStateClosed,
            "a close with nothing to deliver must end at once");
    require(world.end[0].closed_calls == 1 && world.end[0].close_reason == kEnetDriverCloseLocal,
            "client must report one local close");

    simAdvance(&world, 1000);
    require(world.end[1].connected_calls == 0 && world.end[1].closed_calls == 0, "server must never see a session");
    simDestroy(&world);
}

static void testAbortTellsPeerOnce(void)
{
    sim_world_t                world;
    const enet_driver_config_t client = simConfig(kEnetDriverRoleClient);
    const enet_driver_config_t server = simConfig(kEnetDriverRoleServer);
    openConnected(&world, &client, &server, 20);
    simAdvance(&world, 100);

    const uint64_t sent_before = world.end[0].datagrams_sent;
    enetDriverAbort(world.end[0].driver, world.now);
    simSchedule(&world.end[0]);
    require(enetDriverState(world.end[0].driver) == kEnetDriverStateClosed, "abort must close the driver");
    require(world.end[0].closed_calls == 0, "abort must not report through the closed sink");
    require(world.end[0].datagrams_sent == sent_before + 1, "abort must send exactly one disconnect datagram");

    require(simAdvanceUntil(&world, 1000, serverClosed), "server did not learn about the abort");
    require(world.end[1].close_reason == kEnetDriverCloseRemote, "server must report a remote close");
    simDestroy(&world);
}

static void testPeerCloseDeliversPrecedingBytes(void)
{
    sim_world_t                world;
    const enet_driver_config_t client = simConfig(kEnetDriverRoleClient);
    const enet_driver_config_t server = simConfig(kEnetDriverRoleServer);
    openConnected(&world, &client, &server, 20);

    uint8_t *bytes = simPattern(120000, 8);
    require(simWrite(&world, 1, bytes, 120000), "server write refused");
    closeEnd(&world, 1);

    require(simAdvanceUntil(&world, 60000, bothClosed), "close did not finish");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, world.end[0].stream_length, 120000, "client did not receive every byte");
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, world.end[0].stream, bytes, 120000, "client stream differs");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT,
                    world.end[0].stream_length_at_close,
                    120000,
                    "client was told about the close before the last bytes");
    require(world.end[0].close_reason == kEnetDriverCloseRemote, "client must report a remote close");
    require(world.end[1].close_reason == kEnetDriverCloseLocal, "server must report a local close");

    free(bytes);
    simDestroy(&world);
}

static void testIdlePingKeepsSessionAndSilenceEndsIt(void)
{
    sim_world_t          world;
    enet_driver_config_t client = simConfig(kEnetDriverRoleClient);
    enet_driver_config_t server = simConfig(kEnetDriverRoleServer);
    client.ping_interval_ms     = 200;
    client.no_recv_timeout_ms   = 1000;
    server.ping_interval_ms     = 200;
    server.no_recv_timeout_ms   = 1000;
    openConnected(&world, &client, &server, 10);

    const uint64_t sent_before = world.end[0].datagrams_sent;
    simAdvance(&world, 3000);
    require(world.end[0].closed_calls == 0 && world.end[1].closed_calls == 0, "a healthy idle session closed");
    /* Three seconds at a 200 ms interval: about 13 pings of its own plus about 13 acknowledgements of the peer's. */
    const uint64_t idle_datagrams = world.end[0].datagrams_sent - sent_before;
    require(idle_datagrams >= 20 && idle_datagrams <= 40, "idle keepalive rate does not follow ping_interval_ms");

    world.cut             = true;
    const uint64_t cut_at = world.now;
    require(simAdvanceUntil(&world, 200 + 2 * 1000 + 500, bothClosed),
            "a silent link did not end the session within ping interval + 2T");
    require(world.now - cut_at >= 900, "the session ended before the configured timeout");
    require(world.end[0].close_reason == kEnetDriverCloseRemote, "client must report a remote close");
    require(world.end[1].close_reason == kEnetDriverCloseRemote, "server must report a remote close");
    simDestroy(&world);
}

static void testIdleDriverSleepsUntilThePingDeadline(void)
{
    sim_world_t                world;
    const enet_driver_config_t client = simConfig(kEnetDriverRoleClient);
    const enet_driver_config_t server = simConfig(kEnetDriverRoleServer);
    openConnected(&world, &client, &server, 20);
    simAdvance(&world, 100);

    const uint32_t idle_delay = enetDriverNextServiceDelayMs(world.end[0].driver, world.now);
    require(idle_delay > 1000 && idle_delay <= 10000,
            "an idle connected driver must sleep until its ping deadline, not tick");

    static const uint8_t byte = 1;
    world.cut                 = true;
    require(simWrite(&world, 0, &byte, 1), "write refused");
    require(enetDriverNextServiceDelayMs(world.end[0].driver, world.now) == kEnetDriverActiveTickMs,
            "unacknowledged bytes need the active tick");
    simDestroy(&world);
}

static void testRefusedDatagramsAreRecoveredAsLoss(void)
{
    sim_world_t                world;
    const enet_driver_config_t client = simConfig(kEnetDriverRoleClient);
    const enet_driver_config_t server = simConfig(kEnetDriverRoleServer);
    openConnected(&world, &client, &server, 20);
    simAdvance(&world, 100);

    uint8_t *bytes                = simPattern(20000, 11);
    world.end[0].refuse_datagrams = 5;
    require(simWrite(&world, 0, bytes, 20000), "write refused");

    expected_bytes[0] = 0;
    expected_bytes[1] = 20000;
    require(simAdvanceUntil(&world, 60000, expectedBytesArrived), "bytes did not arrive after refused datagrams");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, world.end[1].stream_length, 20000, "server received a different length");
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, world.end[1].stream, bytes, 20000, "server stream differs");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT,
                    (uint32_t) enetDriverDroppedDatagrams(world.end[0].driver),
                    5,
                    "refused datagrams were not counted");
    require(world.end[0].closed_calls == 0 && world.end[1].closed_calls == 0,
            "a refused datagram must not close the session");

    free(bytes);
    simDestroy(&world);
}

static void testTransferSurvivesLossDuplicationAndReordering(void)
{
    enum
    {
        kTotal = 400000,
        kPiece = 20000
    };
    sim_world_t                world;
    const enet_driver_config_t client = simConfig(kEnetDriverRoleClient);
    const enet_driver_config_t server = simConfig(kEnetDriverRoleServer);
    openConnected(&world, &client, &server, 20);
    world.loss_permille      = 50;
    world.duplicate_permille = 50;
    world.jitter_ms          = 30;

    uint8_t *up   = simPattern(kTotal, 9);
    uint8_t *down = simPattern(kTotal, 10);
    for (size_t offset = 0; offset < kTotal; offset += kPiece)
    {
        require(simWrite(&world, 0, up + offset, kPiece), "client write refused");
        require(simWrite(&world, 1, down + offset, kPiece), "server write refused");
        simAdvance(&world, 5);
    }

    expected_bytes[0] = kTotal;
    expected_bytes[1] = kTotal;
    require(simAdvanceUntil(&world, 600000, expectedBytesArrived), "bytes did not arrive over the impaired link");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, world.end[1].stream_length, kTotal, "server received a different length");
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, world.end[1].stream, up, kTotal, "server stream differs");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, world.end[0].stream_length, kTotal, "client received a different length");
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, world.end[0].stream, down, kTotal, "client stream differs");
    require(world.end[0].closed_calls == 0 && world.end[1].closed_calls == 0, "session closed on an impaired link");

    free(up);
    free(down);
    simDestroy(&world);
}

/* ENet acknowledges what arrives after a lost command, so the sender keeps going, and at the waiting-data limit
 * ENet refuses every new command. The lost command must still be accepted when it arrives again. */
static void testLostCommandPassesTheReceiveLimit(void)
{
    enum
    {
        kBulk = 4 * kEnetDriverMaxMessage
    };
    sim_world_t                world;
    const enet_driver_config_t client = simConfig(kEnetDriverRoleClient);
    enet_driver_config_t       server = simConfig(kEnetDriverRoleServer);
    server.receive_buffer_limit       = kEnetDriverReceiveBufferMin; /* room for two messages of the largest size */
    openConnected(&world, &client, &server, 20);
    simAdvance(&world, 100);

    /* One byte travels alone in a small datagram, which is lost. The bulk behind it fills the receive limit long
     * before ENet sends the byte again. */
    uint8_t *bytes          = simPattern(1 + kBulk, 12);
    world.end[0].lose_small = 1;
    require(simWrite(&world, 0, bytes, 1), "write refused");
    simAdvance(&world, 2);
    require(world.end[0].lose_small == 0, "the single byte did not travel in a datagram of its own");
    require(simWrite(&world, 0, bytes + 1, kBulk), "write refused");

    expected_bytes[0] = 0;
    expected_bytes[1] = 1 + kBulk;
    require(simAdvanceUntil(&world, 20000, expectedBytesArrived),
            "the stream stalled behind a lost command at the receive limit");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, world.end[1].stream_length, 1 + kBulk, "server received a different length");
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, world.end[1].stream, bytes, 1 + kBulk, "server stream differs");
    require(world.end[0].closed_calls == 0 && world.end[1].closed_calls == 0, "the session closed");

    free(bytes);
    simDestroy(&world);
}

int main(void)
{
    TEST_RUN_CASE(testHandshakeCompletes);
    TEST_RUN_CASE(testConnectRequestIsNativeAndCarriesSettings);
    TEST_RUN_CASE(testStreamRoundTripInOrder);
    TEST_RUN_CASE(testWriteBeforeHandshakeIsDelivered);
    TEST_RUN_CASE(testSendHoldHysteresisAndHardCap);
    TEST_RUN_CASE(testGracefulCloseDeliversEverything);
    TEST_RUN_CASE(testCloseBeforeHandshakeStillDelivers);
    TEST_RUN_CASE(testCloseBeforeHandshakeWithoutBytesEndsNow);
    TEST_RUN_CASE(testAbortTellsPeerOnce);
    TEST_RUN_CASE(testPeerCloseDeliversPrecedingBytes);
    TEST_RUN_CASE(testIdlePingKeepsSessionAndSilenceEndsIt);
    TEST_RUN_CASE(testIdleDriverSleepsUntilThePingDeadline);
    TEST_RUN_CASE(testRefusedDatagramsAreRecoveredAsLoss);
    TEST_RUN_CASE(testTransferSurvivesLossDuplicationAndReordering);
    TEST_RUN_CASE(testLostCommandPassesTheReceiveLimit);
    return 0;
}
