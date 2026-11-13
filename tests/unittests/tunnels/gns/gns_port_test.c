/* CTest: waterwall.gns_port_unit.
 * The port between GameNetworkingSockets' threads and a session's worker, and the engine calls on top of it.
 * First the port alone, fed from a second thread: the bound of its list, the refusal that tells GNS to offer a
 * datagram again, one wake for many arrivals, no wake while the owner is at it, an owner that yields, and a wake
 * that is still on its way when the session ends. Then two ports joined by hand under the real library: listen,
 * connect, the accept callback with its token, data in both directions, status, close, and a token that has gone
 * stale. */

#include "GnsCommon/engine.h"
#include "GnsCommon/port.h"

#include "gns_runtime.h"

enum
{
    kMessageBytes = 65536,
    kStreamBytes  = 262144,
    kWindowBytes  = 131072, /* the sender stays this far ahead of the receiver at most; GNS has no flow control */
};

static void countWake(void *user)
{
    ++*(uint32_t *) user;
}

static void stepUntil(const uint32_t *counter, uint32_t value)
{
    const uint64_t deadline = gnsTestNowMs() + kGnsTestDeadlineMs;
    while (*counter != value)
    {
        gnsRequire(gnsTestNowMs() < deadline, "a wake did not reach the worker");
        gnsTestStep();
        wwSleepMS(1);
    }
}

typedef struct producer_s
{
    gns_port_t *port;
    uint32_t    first;
    uint32_t    count;
    uint32_t    accepted;
    uint32_t    refused;
} producer_t;

/* What a GNS thread does: hand datagrams to the port and return. */
static WTHREAD_ROUTINE(produce)
{
    producer_t *producer = userdata;
    for (uint32_t i = 0; i < producer->count; ++i)
    {
        const uint32_t value = producer->first + i;
        if (gnsPortSend(producer->port, (const uint8_t *) &value, sizeof(value), NULL))
        {
            ++producer->accepted;
        }
        else
        {
            ++producer->refused;
        }
    }
    return 0;
}

static void produceFromAnotherThread(producer_t *producer)
{
    wthread_t thread;
    gnsRequire(threadCreate(&thread, produce, producer) == kWThreadErrorNone, "the producer thread did not start");
    threadJoin(thread);
}

/* Takes what the port holds and checks that the datagrams carry first, first + 1, ... in order. */
static uint32_t takeSequence(gns_port_t *port, uint32_t first)
{
    uint32_t             incoming;
    uint32_t             count = 0;
    gns_port_datagram_t *list  = gnsPortTake(port, &incoming);
    gnsRequire(incoming == 0, "a port reported a connection that nobody made");
    while (list != NULL)
    {
        gns_port_datagram_t *next = list->next;
        uint32_t             value;
        gnsRequire(list->length == sizeof(value), "a datagram changed its length in the port");
        memoryCopy(&value, list->bytes, sizeof(value));
        gnsRequire(value == first + count, "datagrams left the port out of order");
        gnsPortDatagramFree(list);
        list = next;
        ++count;
    }
    return count;
}

static void testBoundAndWake(void)
{
    uint32_t    wakes = 0;
    gns_port_t *port  = gnsPortCreate(0, 16, countWake, &wakes);

    /* Forty datagrams from another thread: sixteen fit, the rest are refused, and the worker hears once. */
    producer_t burst = {.port = port, .first = 100, .count = 40};
    produceFromAnotherThread(&burst);
    gnsRequire(burst.accepted == 16 && burst.refused == 24, "the list did not stop at its limit");
    gnsRequire(gnsPortRefusedDatagrams(port) == 24, "refused datagrams were not counted");
    gnsRequire(wakes == 0, "a wake ran on the producer's thread");
    stepUntil(&wakes, 1);
    gnsTestStep();
    gnsRequire(wakes == 1, "many arrivals posted more than one wake");

    gnsPortEnter(port);
    gnsRequire(takeSequence(port, 100) == 16, "the port lost or invented datagrams");
    gnsRequire(gnsPortLeave(port), "an empty port did not let its owner leave");

    /* While the owner is at it, arrivals post nothing: the owner sees them before it leaves. */
    gnsPortEnter(port);
    producer_t during = {.port = port, .first = 200, .count = 5};
    produceFromAnotherThread(&during);
    gnsTestStep();
    gnsRequire(wakes == 1, "an arrival woke a worker that was already draining");
    gnsRequire(! gnsPortLeave(port), "the owner left although something had arrived");
    gnsRequire(takeSequence(port, 200) == 5, "datagrams that arrived during a drain were lost");
    gnsRequire(gnsPortLeave(port), "a drained port did not let its owner leave");

    /* After the owner left, the next arrival wakes it again. */
    producer_t after = {.port = port, .first = 300, .count = 1};
    produceFromAnotherThread(&after);
    stepUntil(&wakes, 2);
    gnsPortEnter(port);
    gnsRequire(takeSequence(port, 300) == 1, "the datagram behind the second wake is missing");
    gnsRequire(gnsPortLeave(port), "a drained port did not let its owner leave");

    /* An owner that has to let other work run yields: it leaves at once and one wake brings it back. */
    gnsPortEnter(port);
    producer_t waiting = {.port = port, .first = 400, .count = 3};
    produceFromAnotherThread(&waiting);
    gnsPortYield(port);
    stepUntil(&wakes, 3);
    gnsPortEnter(port);
    gnsRequire(takeSequence(port, 400) == 3, "datagrams behind a yield are missing");
    gnsRequire(gnsPortLeave(port), "a drained port did not let its owner leave");
    gnsPortEnter(port);
    gnsPortYield(port);
    gnsTestStep();
    gnsRequire(wakes == 3, "a yield without news posted a wake");

    gnsPortDetach(port);
    gnsPortRelease(port);
}

/* The session can end while a wake for it is on its way. The wake must find nothing to call. */
static void testDetachBeforeWake(void)
{
    uint32_t    wakes   = 0;
    gns_port_t *port    = gnsPortCreate(0, 4, countWake, &wakes);
    producer_t  arrival = {.port = port, .first = 1, .count = 3};
    produceFromAnotherThread(&arrival);
    gnsPortDetach(port);
    gnsPortRelease(port);
    for (int i = 0; i < 20; ++i)
    {
        gnsTestStep();
        wwSleepMS(1);
    }
    gnsRequire(wakes == 0, "a detached port woke its owner");

    /* A detached port takes a datagram as sent and keeps nothing. */
    gns_port_t *gone = gnsPortCreate(0, 4, countWake, &wakes);
    gnsPortDetach(gone);
    const uint8_t byte = 7;
    gnsRequire(gnsPortSend(gone, &byte, 1, NULL), "a detached port refused a datagram");
    gnsPortRelease(gone);
    gnsTestStep();
    gnsRequire(wakes == 0, "a detached port woke its owner");
}

/* One end of a connection: its port, its endpoint and what it learned from them. */
typedef struct side_s
{
    gns_port_t              *port;
    gns_external_endpoint_t *endpoint;
    uint32_t                 listen;
    uint32_t                 connection;
    uint32_t                 wakes;
} side_t;

static const gns_external_addr_t kServerAddress = {.ip = {0xfd, [15] = 1}, .port = 4000};
static const gns_external_addr_t kClientAddress = {.ip = {0xfd, [15] = 2}, .port = 5000};

static const gns_engine_options_t kOptions = {
    .packet_size          = 1300,
    .send_rate            = 20 * 1000 * 1000,
    .timeout_initial_ms   = 10000,
    .timeout_connected_ms = 10000,
    .receive_buffer       = 1048576,
    .receive_messages     = 4096,
    .receive_message_max  = 524288,
};

/* Plays the worker of one side: takes what its port holds and carries the datagrams to the other endpoint. */
static void carry(side_t *from, side_t *to, const gns_external_addr_t *source)
{
    gnsPortEnter(from->port);
    do
    {
        uint32_t             incoming;
        gns_port_datagram_t *list = gnsPortTake(from->port, &incoming);
        if (incoming != 0)
        {
            from->connection = incoming;
        }
        while (list != NULL)
        {
            gns_port_datagram_t *next = list->next;
            if (to != NULL)
            {
                /* False means that nothing is bound to the endpoint any more: the datagram is lost. */
                discard gns_external_receive(to->endpoint, source, list->bytes, list->length);
            }
            gnsPortDatagramFree(list);
            list = next;
        }
    } while (! gnsPortLeave(from->port));
}

static void pump(side_t *server, side_t *client)
{
    gnsTestStep();
    gnsEngineRunAccepts();
    carry(client, server, &kClientAddress);
    carry(server, client, NULL);
}

static gns_engine_state_t stateOf(uint32_t connection)
{
    gns_engine_status_t status;
    gnsEngineStatus(connection, &status);
    return status.state;
}

static uint8_t patternByte(size_t offset, uint8_t seed)
{
    return (uint8_t) (offset * 31U + seed);
}

static void transfer(side_t *server, side_t *client, uint32_t from, uint32_t to, uint8_t seed)
{
    static uint8_t message[kMessageBytes];
    size_t         sent     = 0;
    size_t         received = 0;
    const uint64_t deadline = gnsTestNowMs() + kGnsTestDeadlineMs;
    while (received < kStreamBytes)
    {
        gnsRequire(gnsTestNowMs() < deadline, "the transfer did not finish");
        bool progress = false;
        if (sent < kStreamBytes && sent - received < kWindowBytes)
        {
            for (size_t i = 0; i < kMessageBytes; ++i)
            {
                message[i] = patternByte(sent + i, seed);
            }
            gnsRequire(gnsEngineSend(from, message, kMessageBytes) == kGnsEngineSendAccepted,
                       "the library refused a message below every limit");
            sent += kMessageBytes;
            progress = true;
        }
        pump(server, client);
        gns_engine_message_t messages[8];
        const int            count = gnsEngineReceive(to, messages, 8);
        for (int i = 0; i < count; ++i)
        {
            for (uint32_t offset = 0; offset < messages[i].size; ++offset)
            {
                gnsRequire(messages[i].data[offset] == patternByte(received + offset, seed),
                           "received bytes differ from the bytes that were sent");
            }
            received += messages[i].size;
            progress = true;
        }
        gnsEngineMessagesRelease(messages, count);
        if (! progress)
        {
            wwSleepMS(1);
        }
    }
    gnsRequire(received == kStreamBytes, "more bytes arrived than were sent");
}

#define pumpUntil(condition, message)                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        const uint64_t pump_deadline = gnsTestNowMs() + kGnsTestDeadlineMs;                                            \
        while (! (condition))                                                                                          \
        {                                                                                                              \
            gnsRequire(gnsTestNowMs() < pump_deadline, message);                                                       \
            pump(&server, &client);                                                                                    \
            wwSleepMS(1);                                                                                              \
        }                                                                                                              \
    } while (0)

static void sideOpen(side_t *side)
{
    *side      = (side_t) {0};
    side->port = gnsPortCreate(0, 256, countWake, &side->wakes);
}

static void sideClose(side_t *side)
{
    gnsPortDetach(side->port);
    gns_external_endpoint_release(side->endpoint);
    gnsPortRelease(side->port);
}

static void testEngineOverPorts(void)
{
    side_t server;
    side_t client;
    sideOpen(&server);
    sideOpen(&client);
    server.endpoint = gns_external_endpoint_create_listen(&kServerAddress, gnsPortSend, server.port);
    client.endpoint = gns_external_endpoint_create_connect(&kServerAddress, gnsPortSend, client.port);
    gnsRequire(server.endpoint != NULL && client.endpoint != NULL, "an endpoint was not registered");

    server.listen = gnsEngineListen(&kServerAddress, &kOptions, gnsPortToken(server.port));
    gnsRequire(server.listen != 0, "the listen socket did not open on its endpoint");
    client.connection = gnsEngineConnect(&kServerAddress, &kOptions);
    gnsRequire(client.connection != 0, "the connection did not start on its endpoint");
    gnsRequire(stateOf(client.connection) == kGnsEngineConnecting, "a new connection is not connecting");

    /* The accept callback finds the server's port through the token and leaves the handle there. */
    pumpUntil(server.connection != 0, "the incoming connection never reached the server's port");
    pumpUntil(stateOf(client.connection) == kGnsEngineConnected && stateOf(server.connection) == kGnsEngineConnected,
              "the handshake did not finish");

    transfer(&server, &client, client.connection, server.connection, 7);
    transfer(&server, &client, server.connection, client.connection, 91);
    gnsRequire(server.wakes > 0 && client.wakes > 0, "the library's own thread never woke the worker");

    /* Everything that was sent is acknowledged in the end; this is what the session's pressure reads. */
    gns_engine_status_t status;
    gnsEngineStatus(client.connection, &status);
    pumpUntil((gnsEngineStatus(client.connection, &status), status.queued_bytes + status.unacked_bytes == 0),
              "acknowledged data stayed counted as outstanding");

    /* Close from the client. The server sees it and can still read why. The library keeps a closed connection for
     * a few seconds; both sides let go of their endpoints before that. */
    gnsEngineClose(client.connection);
    gnsRequire(stateOf(client.connection) == kGnsEngineGone, "a closed connection still answers");
    pumpUntil(stateOf(server.connection) == kGnsEngineClosedByPeer, "the server did not see the close");
    char reason[128];
    gnsRequire(gnsEngineEndReason(server.connection, reason, sizeof(reason)) != 0, "a closed connection has no reason");
    gnsEngineClose(server.connection);
    gnsRequire(stateOf(server.connection) == kGnsEngineGone, "a closed connection still answers");
    gnsEngineCloseListen(server.listen);

    sideClose(&server);
    sideClose(&client);
}

/* A listen socket whose session has ended refuses what still arrives for it: the token names nothing. */
static void testStaleToken(void)
{
    side_t gone;
    sideOpen(&gone);
    const int64_t stale = gnsPortToken(gone.port);
    gnsPortDetach(gone.port);
    gnsPortRelease(gone.port);

    side_t server;
    side_t client;
    sideOpen(&server);
    sideOpen(&client);
    server.endpoint = gns_external_endpoint_create_listen(&kServerAddress, gnsPortSend, server.port);
    client.endpoint = gns_external_endpoint_create_connect(&kServerAddress, gnsPortSend, client.port);
    gnsRequire(server.endpoint != NULL && client.endpoint != NULL, "an endpoint was not registered");
    server.listen     = gnsEngineListen(&kServerAddress, &kOptions, stale);
    client.connection = gnsEngineConnect(&kServerAddress, &kOptions);
    gnsRequire(server.listen != 0 && client.connection != 0, "the listen socket or the connection did not open");

    pumpUntil(stateOf(client.connection) == kGnsEngineClosedByPeer || stateOf(client.connection) == kGnsEngineFailed,
              "a connection behind a stale token was not turned away");
    gnsRequire(server.connection == 0, "a stale token delivered a connection to a port");

    gnsEngineClose(client.connection);
    gnsEngineCloseListen(server.listen);
    sideClose(&server);
    sideClose(&client);
}

int main(void)
{
    gnsTestRuntimeStart();
    gnsRequire(gnsRuntimeAcquire("GnsTest"), "GameNetworkingSockets did not start");
    TEST_RUN_CASE(testBoundAndWake);
    TEST_RUN_CASE(testDetachBeforeWake);
    TEST_RUN_CASE(testEngineOverPorts);
    TEST_RUN_CASE(testStaleToken);
    gnsRuntimeRelease();
    /* A second start of the library and the token table after a complete stop. */
    gnsRequire(gnsRuntimeAcquire("GnsTest"), "GameNetworkingSockets did not start a second time");
    TEST_RUN_CASE(testEngineOverPorts);
    gnsRuntimeRelease();
    gnsTestRuntimeStop();
    return 0;
}
