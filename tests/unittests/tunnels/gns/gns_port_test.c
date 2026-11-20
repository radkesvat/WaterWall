/* CTest: waterwall.gns_port_unit.
 * The port between GameNetworkingSockets' threads and a session's worker, and the engine calls on top of it.
 * First the port alone, fed from a second thread: the bound of its list, the refusal that tells GNS to offer a
 * datagram again, one wake for many arrivals, no wake while the owner is at it, an owner that yields, and a wake
 * that is still on its way when the session ends. Then two ports joined by hand under the real library: listen,
 * connect, data in both directions, status, close, and accepts refused by stale tokens or closed admission.
 * On Linux, quiescence races a foreign submission and cancels an already queued wake. */

#include "GnsCommon/engine.h"
#include "GnsCommon/port.h"

#include "gns_runtime.h"

enum
{
    kMessageBytes = 65536,
    kStreamBytes  = 262144,
    kWindowBytes  = 131072, /* the sender stays this far ahead of the receiver at most; GNS has no flow control */
};

static quiescence_gate_t test_admission;

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
    gns_port_t *port  = gnsPortCreate(0, 16, &test_admission, countWake, &wakes);

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
    gns_port_t *port    = gnsPortCreate(0, 4, &test_admission, countWake, &wakes);
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
    gns_port_t *gone = gnsPortCreate(0, 4, &test_admission, countWake, &wakes);
    gnsPortDetach(gone);
    const uint8_t byte = 7;
    gnsRequire(gnsPortSend(gone, &byte, 1, NULL), "a detached port refused a datagram");
    gnsPortRelease(gone);
    gnsTestStep();
    gnsRequire(wakes == 0, "a detached port woke its owner");
}

#ifdef GNS_PORT_TEST_WRAP
static atomic_uintptr_t queued_port;
static atomic_uintptr_t racing_port;
static atomic_bool      at_wake_submission;
static atomic_bool      release_wake_submission;
static atomic_uint      submissions;
static atomic_uint      freed_ports;

worker_message_submit_result_e __real_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback cb,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback cb,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback cb,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3)
{
    const bool queued = arg1 != NULL && (uintptr_t) arg1 == atomicLoadRelaxed(&queued_port);
    const bool racing = arg1 != NULL && (uintptr_t) arg1 == atomicLoadRelaxed(&racing_port);
    if (queued || racing)
    {
        discard atomicIncRelaxed(&submissions);
    }
    if (racing)
    {
        atomicStoreExplicit(&at_wake_submission, true, memory_order_release);
        const uint64_t deadline = gnsTestNowMs() + kGnsTestDeadlineMs;
        while (! atomicLoadExplicit(&release_wake_submission, memory_order_acquire))
        {
            gnsRequire(gnsTestNowMs() < deadline, "shutdown did not release the racing wake");
            wwSleepMS(1);
        }
    }
    const worker_message_submit_result_e result =
        __real_sendWorkerMessageForceQueueWithCleanup(wid, cb, cleanup, arg1, arg2, arg3);
    if (queued || racing)
    {
        gnsRequire(result == (queued ? kWorkerMessageSubmitAccepted : kWorkerMessageSubmitRejectedCleanupRan),
                   "the worker did not settle the wake submission as expected");
    }
    return result;
}

void __real_memoryFree(void *ptr);
void __wrap_memoryFree(void *ptr);

void __wrap_memoryFree(void *ptr)
{
    if (ptr != NULL &&
        ((uintptr_t) ptr == atomicLoadRelaxed(&queued_port) || (uintptr_t) ptr == atomicLoadRelaxed(&racing_port)))
    {
        discard atomicIncRelaxed(&freed_ports);
    }
    __real_memoryFree(ptr);
}

static void releaseRacingWake(void *context)
{
    atomicStoreExplicit(&release_wake_submission, true, memory_order_release);
    quiescenceGateYieldThread(context);
}

/* Keep one wake queued and park a second producer after it reserved its wake reference. The worker cancels
 * the queued wake before the port fence lets the second submission return from its refusal cleanup. */
static void testQuiescenceFence(void)
{
    quiescence_gate_t admission;
    quiescenceGateInit(&admission);
    gnsRequire(quiescenceGateOpen(&admission), "port admission did not open");
    uint32_t    wakes  = 0;
    gns_port_t *queued = gnsPortCreate(0, 16, &admission, countWake, &wakes);
    gns_port_t *racing = gnsPortCreate(0, 16, &admission, countWake, &wakes);
    atomicStoreRelaxed(&queued_port, (uintptr_t) queued);
    atomicStoreRelaxed(&racing_port, (uintptr_t) racing);

    producer_t before = {.port = queued, .first = 10, .count = 1};
    produceFromAnotherThread(&before);
    gnsRequire(before.accepted == 1 && atomicLoadRelaxed(&submissions) == 1 && wakes == 0,
               "shutdown had no already-queued wake");

    producer_t during = {.port = racing, .first = 20, .count = 1};
    wthread_t  thread;
    gnsRequire(threadCreate(&thread, produce, &during) == kWThreadErrorNone, "the racing producer did not start");
    const uint64_t deadline = gnsTestNowMs() + kGnsTestDeadlineMs;
    while (! atomicLoadExplicit(&at_wake_submission, memory_order_acquire))
    {
        gnsRequire(gnsTestNowMs() < deadline, "the racing producer did not reach submission");
        wwSleepMS(1);
    }

    quiescenceGateClose(&admission);
    gnsRequire(! quiescenceGateIsClosedAndQuiesced(&admission), "the callback left admission before posting its wake");
    const ww_lifecycle_context_t *context = wwLifecycleStartupRollback();
    gnsRequire(workerInstallApplicationQuiesceRequest(getWorker(0), context) != kWorkerQuiesceRequestUnavailable,
               "the worker refused quiescence");
    workerPerformQuiesce(getWorker(0), context);
    quiescenceGateWaitQuiesced(&admission, releaseRacingWake, NULL);
    threadJoin(thread);
    gnsRequire(during.accepted == 1 && wakes == 0, "an admitted wake ran during worker quiescence");

    producer_t after_queue = {.port = queued, .first = 30, .count = 3};
    producer_t after_race  = {.port = racing, .first = 40, .count = 3};
    produceFromAnotherThread(&after_queue);
    produceFromAnotherThread(&after_race);
    gnsPortEnter(queued);
    gnsPortYield(queued);
    gnsRequire(takeSequence(queued, 10) == 1 && takeSequence(racing, 20) == 1,
               "a port took new datagrams after the quiescence fence");
    gnsRequire(atomicLoadRelaxed(&submissions) == 2, "a port submitted a new wake after the quiescence fence");
    gnsRequire(atomicLoadRelaxed(&freed_ports) == 0, "a wake released an owner reference");
    gnsPortDetach(queued);
    gnsPortRelease(queued);
    gnsPortDetach(racing);
    gnsPortRelease(racing);
    gnsRequire(atomicLoadRelaxed(&freed_ports) == 2, "a wake stranded a port reference");
    atomicStoreRelaxed(&queued_port, 0);
    atomicStoreRelaxed(&racing_port, 0);
}
#endif

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
    side->port = gnsPortCreate(0, 256, &test_admission, countWake, &side->wakes);
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

static void requireRefusedToken(int64_t token)
{
    side_t server;
    side_t client;
    sideOpen(&server);
    sideOpen(&client);
    server.endpoint = gns_external_endpoint_create_listen(&kServerAddress, gnsPortSend, server.port);
    client.endpoint = gns_external_endpoint_create_connect(&kServerAddress, gnsPortSend, client.port);
    gnsRequire(server.endpoint != NULL && client.endpoint != NULL, "an endpoint was not registered");
    server.listen     = gnsEngineListen(&kServerAddress, &kOptions, token);
    client.connection = gnsEngineConnect(&kServerAddress, &kOptions);
    gnsRequire(server.listen != 0 && client.connection != 0, "the listen socket or the connection did not open");

    pumpUntil(stateOf(client.connection) != kGnsEngineConnecting, "the peer never settled the connection attempt");
    gnsRequire(stateOf(client.connection) == kGnsEngineClosedByPeer, "the peer did not refuse the connection");

    gnsEngineClose(client.connection);
    gnsEngineCloseListen(server.listen);
    sideClose(&server);
    sideClose(&client);
}

/* A listen socket whose session has ended refuses what still arrives for it: the token names nothing. */
static void testStaleToken(void)
{
    uint32_t      wakes = 0;
    gns_port_t   *gone  = gnsPortCreate(0, 4, &test_admission, countWake, &wakes);
    const int64_t stale = gnsPortToken(gone);
    gnsPortDetach(gone);
    gnsPortRelease(gone);
    requireRefusedToken(stale);
}

/* Keep the wire on an open port so the native handshake reaches the accept callback and carries its refusal. */
static void testClosedAdmissionToken(void)
{
    quiescence_gate_t admission;
    quiescenceGateInit(&admission);
    gnsRequire(quiescenceGateOpen(&admission), "port admission did not open");
    uint32_t    wakes  = 0;
    gns_port_t *closed = gnsPortCreate(0, 4, &admission, countWake, &wakes);
    quiescenceGateCloseAndQuiesce(&admission, quiescenceGateYieldThread, NULL);
    requireRefusedToken(gnsPortToken(closed));
    gnsRequire(takeSequence(closed, 0) == 0 && wakes == 0, "closed admission published an incoming connection");
    gnsPortDetach(closed);
    gnsPortRelease(closed);
}

int main(void)
{
    quiescenceGateInit(&test_admission);
    gnsRequire(quiescenceGateOpen(&test_admission), "port admission did not open");
    gnsTestRuntimeStart();
    gnsRequire(gnsRuntimeAcquire("GnsTest"), "GameNetworkingSockets did not start");
    TEST_RUN_CASE(testBoundAndWake);
    TEST_RUN_CASE(testDetachBeforeWake);
    TEST_RUN_CASE(testEngineOverPorts);
    TEST_RUN_CASE(testStaleToken);
    TEST_RUN_CASE(testClosedAdmissionToken);
    gnsRuntimeRelease();
    /* A second start of the library and the token table after a complete stop. */
    gnsRequire(gnsRuntimeAcquire("GnsTest"), "GameNetworkingSockets did not start a second time");
    TEST_RUN_CASE(testEngineOverPorts);
#ifdef GNS_PORT_TEST_WRAP
    TEST_RUN_CASE(testQuiescenceFence);
#endif
    gnsRuntimeRelease();
    quiescenceGateCloseAndQuiesce(&test_admission, quiescenceGateYieldThread, NULL);
    gnsTestRuntimeStop();
    return 0;
}
