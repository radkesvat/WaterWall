/* CTest: waterwall.enet_session_unit.
 * Two ENet sessions, a client and a server, joined by an in-memory wire and driven by an explicit clock: no worker
 * timer, socket or sleep is involved. Covers the handshake, ordered transfer in both directions, calls made from
 * inside a callback, the send hold and its release by acknowledgements, carrier-queue overflow, the hard send cap,
 * graceful close (also before the handshake and from inside a callback) and its deadline, the server's connect
 * deadline, abort and quiescence. */

#include "EnetCommon/session.h"

#include "EnetCommon/driver.h"
#include "enet_runtime.h"

enum
{
    kWireCapacity   = 8192,
    kStreamCapacity = 1024 * 1024,
    kChunk          = 16384
};

typedef struct pair_s pair_t;

typedef struct end_s
{
    pair_t               *pair;
    enet_session_t       *session;
    int                   index;
    uint8_t              *stream; /* everything the payload callback delivered */
    size_t                stream_length;
    size_t                stream_length_at_terminal;
    size_t                sent; /* bytes given to enetSessionSend so far */
    unsigned              connected_calls;
    unsigned              pause_calls;
    unsigned              resume_calls;
    unsigned              terminal_calls;
    unsigned              emitted;
    enet_session_result_t result;
    bool                  echo;             /* send every received buffer back from inside the payload callback */
    bool                  reply_and_finish; /* answer the next payload and finish, both from inside it */
} end_t;

struct pair_s
{
    end_t    end[2]; /* 0 is the client, 1 is the server */
    uint64_t now;
    bool     cut;    /* every datagram is lost */
    bool     direct; /* datagrams are delivered from inside the emit callback */
    sbuf_t  *wire[kWireCapacity];
    int      wire_to[kWireCapacity];
    size_t   wire_count;
};

static uint8_t patternByte(size_t offset)
{
    return (uint8_t) (offset * 29U + 17U);
}

static uint64_t pairNow(void *clock_user)
{
    return ((pair_t *) clock_user)->now;
}

static void endEmit(void *user, sbuf_t *packet)
{
    end_t  *end  = user;
    pair_t *pair = end->pair;
    end_t  *peer = &pair->end[1 - end->index];
    end->emitted += 1;
    if (pair->cut || ! enetSessionIsAlive(peer->session))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(0), packet);
        return;
    }
    if (pair->direct)
    {
        enetSessionInput(peer->session, packet);
        return;
    }
    enetRequire(pair->wire_count < kWireCapacity, "the test wire overflowed");
    pair->wire[pair->wire_count]    = packet;
    pair->wire_to[pair->wire_count] = peer->index;
    pair->wire_count += 1;
}

static void pairSend(pair_t *pair, int from, size_t size);

static void endPayload(void *user, sbuf_t *payload)
{
    end_t       *end    = user;
    const size_t length = sbufGetLength(payload);
    enetRequire(length > 0 && end->stream_length + length <= kStreamCapacity, "unexpected payload size");
    memcpy(end->stream + end->stream_length, sbufGetRawPtr(payload), length);
    end->stream_length += length;
    if (end->reply_and_finish)
    {
        end->reply_and_finish = false;
        bufferpoolReuseBuffer(getWorkerBufferPool(0), payload);
        pairSend(end->pair, end->index, kChunk);
        enetSessionAppFinish(end->session);
        return;
    }
    if (end->echo)
    {
        enetSessionSend(end->session, payload);
        return;
    }
    bufferpoolReuseBuffer(getWorkerBufferPool(0), payload);
}

static void endConnected(void *user)
{
    ((end_t *) user)->connected_calls += 1;
}

static void endPressure(void *user, bool paused)
{
    end_t *end = user;
    enetRequire(enetSessionIsPressured(end->session) == paused, "the hold was not published before its callback");
    if (paused)
    {
        end->pause_calls += 1;
    }
    else
    {
        end->resume_calls += 1;
    }
}

static void endTerminal(void *user, enet_session_result_t result)
{
    end_t *end = user;
    end->terminal_calls += 1;
    end->result                    = result;
    end->stream_length_at_terminal = end->stream_length;
}

static enet_settings_t testSettings(void)
{
    return (enet_settings_t) {
        .send_mtu               = 1500,
        .host_mtu               = 1472,
        .ping_interval_ms       = 100,
        .no_recv_timeout_ms     = 2000,
        .send_buffer_limit      = 65536,
        .receive_buffer_limit   = 1048576,
        .carrier_queue_limit    = 256,
        .close_drain_timeout_ms = 500,
    };
}

static void pairOpen(pair_t *pair, const enet_settings_t *client, const enet_settings_t *server)
{
    memset(pair, 0, sizeof(*pair));
    pair->now = 1000;
    for (int i = 0; i < 2; ++i)
    {
        end_t *end  = &pair->end[i];
        end->pair   = pair;
        end->index  = i;
        end->stream = malloc(kStreamCapacity);
        enetRequire(end->stream != NULL, "out of memory");
        const enet_session_config_t config = {
            .settings   = i == 0 ? *client : *server,
            .client     = i == 0,
            .pool       = getWorkerBufferPool(0),
            .now        = pairNow,
            .clock_user = pair,
        };
        const enet_session_callbacks_t callbacks = {
            .emit      = endEmit,
            .payload   = endPayload,
            .connected = endConnected,
            .pressure  = endPressure,
            .terminal  = endTerminal,
        };
        end->session = enetSessionCreate(&config, &callbacks, end);
        enetRequire(end->session != NULL, "session creation failed");
    }
    enetSessionStart(pair->end[1].session);
    enetSessionStart(pair->end[0].session);
}

/* Delivers queued datagrams until the wire is empty; each delivery can queue more. */
static void pairPump(pair_t *pair)
{
    while (pair->wire_count > 0)
    {
        const size_t count = pair->wire_count;
        sbuf_t     **batch = malloc(count * sizeof(*batch));
        int         *to    = malloc(count * sizeof(*to));
        enetRequire(batch != NULL && to != NULL, "out of memory");
        memcpy(batch, pair->wire, count * sizeof(*batch));
        memcpy(to, pair->wire_to, count * sizeof(*to));
        pair->wire_count = 0;
        for (size_t i = 0; i < count; ++i)
        {
            if (pair->cut || ! enetSessionIsAlive(pair->end[to[i]].session))
            {
                bufferpoolReuseBuffer(getWorkerBufferPool(0), batch[i]);
            }
            else
            {
                enetSessionInput(pair->end[to[i]].session, batch[i]);
            }
        }
        free(batch);
        free(to);
    }
}

/* Advances virtual time one millisecond at a time: both sessions tick, then the wire is emptied. */
static void pairAdvance(pair_t *pair, unsigned milliseconds)
{
    for (unsigned i = 0; i < milliseconds; ++i)
    {
        pair->now += 1;
        enetSessionTick(pair->end[0].session, pair->now);
        enetSessionTick(pair->end[1].session, pair->now);
        pairPump(pair);
    }
}

static bool pairAdvanceUntil(pair_t *pair, unsigned limit_ms, bool (*done)(const pair_t *pair))
{
    pairPump(pair);
    for (unsigned i = 0; i < limit_ms && ! done(pair); ++i)
    {
        pairAdvance(pair, 1);
    }
    return done(pair);
}

static void pairSend(pair_t *pair, int from, size_t size)
{
    end_t  *end     = &pair->end[from];
    sbuf_t *payload = bufferpoolGetBestFit(getWorkerBufferPool(0), size, 0);
    for (size_t i = 0; i < size; ++i)
    {
        sbufGetMutablePtr(payload)[i] = patternByte(end->sent + i);
    }
    sbufSetLength(payload, size);
    end->sent += size;
    enetSessionSend(end->session, payload);
}

static void pairRequireStream(const end_t *receiver, size_t length, const char *message)
{
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, receiver->stream_length, length, message);
    for (size_t i = 0; i < length; ++i)
    {
        if (receiver->stream[i] != patternByte(i))
        {
            enetRequire(false, "the stream changed or was reordered");
        }
    }
}

static void pairClose(pair_t *pair)
{
    for (int i = 0; i < 2; ++i)
    {
        end_t *end = &pair->end[i];
        enetSessionAbort(end->session, kEnetSessionAborted);
        enetRequire(end->terminal_calls == 1, "the terminal callback did not run exactly once");
        enetSessionRelease(end->session);
        free(end->stream);
    }
    for (size_t i = 0; i < pair->wire_count; ++i)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(0), pair->wire[i]);
    }
}

static bool bothConnected(const pair_t *pair)
{
    return pair->end[0].connected_calls == 1 && pair->end[1].connected_calls == 1;
}

static bool bothTerminal(const pair_t *pair)
{
    return pair->end[0].terminal_calls == 1 && pair->end[1].terminal_calls == 1;
}

static bool clientTerminal(const pair_t *pair)
{
    return pair->end[0].terminal_calls == 1;
}

static bool serverTerminal(const pair_t *pair)
{
    return pair->end[1].terminal_calls == 1;
}

static bool clientResumed(const pair_t *pair)
{
    return pair->end[0].resume_calls == 1;
}

static bool transferFinished(const pair_t *pair)
{
    return pair->end[1].stream_length == pair->end[0].sent && pair->end[0].stream_length == pair->end[1].sent;
}

static void pairConnect(pair_t *pair, const enet_settings_t *client, const enet_settings_t *server)
{
    pairOpen(pair, client, server);
    enetRequire(pairAdvanceUntil(pair, 500, bothConnected), "the native handshake did not finish");
    enetRequire(enetSessionIsConnected(pair->end[0].session) && enetSessionIsConnected(pair->end[1].session),
                "a connected session does not report it");
}

static void testHandshakeAndTransfer(void)
{
    static pair_t         pair;
    const enet_settings_t settings = testSettings();
    pairOpen(&pair, &settings, &settings);
    enetRequire(pair.end[0].emitted == 1 && pair.end[1].emitted == 0, "only the client speaks first");
    enetRequire(pairAdvanceUntil(&pair, 500, bothConnected), "the native handshake did not finish");
    for (int i = 0; i < 6; ++i)
    {
        pairSend(&pair, 0, kChunk);
    }
    for (int i = 0; i < 3; ++i)
    {
        pairSend(&pair, 1, kChunk);
    }
    enetRequire(pairAdvanceUntil(&pair, 3000, transferFinished), "the transfer did not finish");
    pairRequireStream(&pair.end[1], 6 * kChunk, "the server received a different length");
    pairRequireStream(&pair.end[0], 3 * kChunk, "the client received a different length");
    enetRequire(pair.end[0].terminal_calls == 0 && pair.end[1].terminal_calls == 0, "a session ended early");
    pairClose(&pair);
}

static void testNestedSendKeepsOrder(void)
{
    static pair_t         pair;
    const enet_settings_t settings = testSettings();
    pairConnect(&pair, &settings, &settings);
    /* The server answers from inside its payload callback, and datagrams arrive inside emit callbacks. */
    pair.end[1].echo = true;
    pair.direct      = true;
    for (int i = 0; i < 4; ++i)
    {
        pairSend(&pair, 0, kChunk);
    }
    pair.end[1].sent = pair.end[0].sent;
    enetRequire(pairAdvanceUntil(&pair, 3000, transferFinished), "the echoed transfer did not finish");
    pairRequireStream(&pair.end[1], 4 * kChunk, "the server received a different length");
    pairRequireStream(&pair.end[0], 4 * kChunk, "the echoed stream came back reordered");
    pairClose(&pair);
}

static void testSendHoldFollowsAcknowledgements(void)
{
    static pair_t         pair;
    const enet_settings_t settings = testSettings();
    pairConnect(&pair, &settings, &settings);
    pair.cut = true;
    for (int i = 0; i < 4; ++i)
    {
        pairSend(&pair, 0, kChunk);
    }
    enetRequire(pair.end[0].pause_calls == 0, "the hold began at the limit instead of above it");
    pairSend(&pair, 0, kChunk);
    enetRequire(pair.end[0].pause_calls == 1 && enetSessionIsPressured(pair.end[0].session),
                "exceeding send-buffer-limit did not start the hold");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT,
                    enetSessionQueuedBytes(pair.end[0].session),
                    5 * (size_t) kChunk,
                    "unacknowledged bytes are not counted");
    /* Nothing more is written. Only the peer's acknowledgements can release the hold. */
    pair.cut = false;
    enetRequire(pairAdvanceUntil(&pair, 1900, clientResumed), "acknowledgements did not release the hold");
    enetRequire(pair.end[0].pause_calls == 1 && ! enetSessionIsPressured(pair.end[0].session),
                "the hold changed more than once");
    enetRequire(pairAdvanceUntil(&pair, 1500, transferFinished), "held bytes were not delivered");
    pairRequireStream(&pair.end[1], 5 * kChunk, "the server received a different length");
    pairClose(&pair);
}

static void testCarrierQueueOverflowRecovers(void)
{
    static pair_t   pair;
    enet_settings_t client     = testSettings();
    enet_settings_t server     = testSettings();
    client.carrier_queue_limit = 4;
    pairConnect(&pair, &client, &server);
    for (int i = 0; i < 2; ++i)
    {
        pairSend(&pair, 0, kChunk);
    }
    enetRequire(enetSessionDroppedDatagrams(pair.end[0].session) > 0, "the carrier queue limit dropped nothing");
    enetRequire(pairAdvanceUntil(&pair, 30000, transferFinished), "ENet did not recover the dropped datagrams");
    pairRequireStream(&pair.end[1], 2 * kChunk, "the server received a different length");
    enetRequire(pair.end[0].terminal_calls == 0 && pair.end[1].terminal_calls == 0,
                "carrier-queue overflow closed the session");
    pairClose(&pair);
}

static void testHardCapEndsTheSender(void)
{
    static pair_t         pair;
    const enet_settings_t settings = testSettings();
    pairConnect(&pair, &settings, &settings);
    pair.cut = true;
    /* The cap is twice the limit, 131072 bytes. Nine chunks leave 147456 queued; the tenth is refused. */
    for (int i = 0; i < 9; ++i)
    {
        pairSend(&pair, 0, kChunk);
    }
    enetRequire(pair.end[0].terminal_calls == 0, "a payload below the hard cap was refused");
    const unsigned emitted = pair.end[0].emitted;
    pairSend(&pair, 0, kChunk);
    enetRequire(pair.end[0].terminal_calls == 1 && pair.end[0].result == kEnetSessionCapacityFailure,
                "a payload above the hard cap did not end the session");
    enetRequire(pair.end[0].emitted == emitted + 1, "the failing session did not send one native disconnect");
    enetRequire(pair.end[1].terminal_calls == 0, "the peer's session ended with it");
    pairClose(&pair);
}

static void testGracefulCloseDeliversFirst(void)
{
    static pair_t   pair;
    enet_settings_t settings        = testSettings();
    settings.send_buffer_limit      = 1048576;
    settings.close_drain_timeout_ms = 5000;
    pairConnect(&pair, &settings, &settings);
    for (int i = 0; i < 12; ++i)
    {
        pairSend(&pair, 0, kChunk);
    }
    enetSessionAppFinish(pair.end[0].session);
    const size_t accepted = pair.end[0].sent;
    pairSend(&pair, 0, kChunk); /* after the finish: dropped */
    pair.end[0].sent = accepted;
    enetRequire(pairAdvanceUntil(&pair, 5000, bothTerminal), "the close did not complete");
    enetRequire(pair.end[0].result == kEnetSessionClosed, "the closing side did not report a local close");
    enetRequire(pair.end[1].result == kEnetSessionPeerClosed, "the peer did not report a peer close");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT,
                    pair.end[1].stream_length_at_terminal,
                    12 * (size_t) kChunk,
                    "the peer heard the close before the last bytes");
    pairRequireStream(&pair.end[1], 12 * kChunk, "the server received a different length");
    pairClose(&pair);
}

static void testFinishBeforeHandshake(void)
{
    static pair_t   pair;
    enet_settings_t settings        = testSettings();
    settings.close_drain_timeout_ms = 5000;
    pairOpen(&pair, &settings, &settings);
    /* The bytes and the finish both arrive before the native handshake. The bytes still go first. */
    pairSend(&pair, 0, kChunk);
    pairSend(&pair, 0, kChunk);
    enetSessionAppFinish(pair.end[0].session);
    enetRequire(pair.end[0].terminal_calls == 0, "a finish with accepted bytes ended the session at once");
    enetRequire(pairAdvanceUntil(&pair, 5000, bothTerminal), "the close did not complete");
    enetRequire(pair.end[0].result == kEnetSessionClosed && pair.end[1].result == kEnetSessionPeerClosed,
                "the close was not reported as local on one side and as a peer close on the other");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT,
                    pair.end[1].stream_length_at_terminal,
                    2 * (size_t) kChunk,
                    "bytes accepted before the handshake were lost");
    pairRequireStream(&pair.end[1], 2 * kChunk, "the server received a different length");
    pairClose(&pair);
}

static void testNestedFinishKeepsQueuedBytes(void)
{
    static pair_t   pair;
    enet_settings_t settings        = testSettings();
    settings.close_drain_timeout_ms = 5000;
    pairConnect(&pair, &settings, &settings);
    /* The server answers and finishes from inside its payload callback. Its answer is still queued when the
     * finish arrives, and it must reach ENet before the close does. */
    pair.end[1].reply_and_finish = true;
    pairSend(&pair, 0, kChunk);
    enetRequire(pairAdvanceUntil(&pair, 5000, bothTerminal), "the close did not complete");
    enetRequire(pair.end[1].result == kEnetSessionClosed && pair.end[0].result == kEnetSessionPeerClosed,
                "the close was not reported as local on one side and as a peer close on the other");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT,
                    pair.end[0].stream_length_at_terminal,
                    (size_t) kChunk,
                    "the answer queued before the finish was lost");
    pairRequireStream(&pair.end[0], kChunk, "the client received a different answer");
    pairClose(&pair);
}

static void testDrainDeadline(void)
{
    static pair_t         pair;
    const enet_settings_t settings = testSettings();
    pairConnect(&pair, &settings, &settings);
    pair.cut = true;
    pairSend(&pair, 0, kChunk);
    enetSessionAppFinish(pair.end[0].session);
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT,
                    (uint32_t) (enetSessionCloseDeadline(pair.end[0].session) - pair.now),
                    500,
                    "the drain deadline is not close-drain-timeout-ms after the finish");
    pairAdvance(&pair, 499);
    enetRequire(pair.end[0].terminal_calls == 0, "the drain ended before its deadline");
    const unsigned emitted = pair.end[0].emitted;
    pairAdvance(&pair, 1);
    enetRequire(pair.end[0].terminal_calls == 1 && pair.end[0].result == kEnetSessionDrainTimeout,
                "the drain deadline did not end the session");
    enetRequire(pair.end[0].emitted == emitted + 1, "the expired drain did not send one native disconnect");
    pairClose(&pair);
}

static void testConnectDeadlines(void)
{
    static pair_t         pair;
    const enet_settings_t settings = testSettings();
    pairOpen(&pair, &settings, &settings);
    pair.cut = true;
    pairPump(&pair);
    pairAdvance(&pair, 1999);
    enetRequire(pair.end[1].terminal_calls == 0, "the server gave up before no-recv-timeout-ms");
    pairAdvance(&pair, 2);
    enetRequire(pair.end[1].terminal_calls == 1 && pair.end[1].result == kEnetSessionConnectTimeout,
                "a server without a native connection did not time out");
    enetRequire(pair.end[1].emitted == 0, "a server that never heard a peer sent a datagram");
    /* The client's connect request is a reliable command: ENet gives up between T and 2T. */
    enetRequire(pairAdvanceUntil(&pair, 2500, clientTerminal), "the client's connect attempt never ended");
    enetRequire(pair.end[0].result == kEnetSessionPeerClosed, "a failed connect is not reported as a peer close");
    pairClose(&pair);
}

static void testAbortIsSilentAndSynchronous(void)
{
    static pair_t         pair;
    const enet_settings_t settings = testSettings();
    pairConnect(&pair, &settings, &settings);
    pairSend(&pair, 0, kChunk);
    const unsigned emitted = pair.end[0].emitted;
    enetSessionAbort(pair.end[0].session, kEnetSessionAborted);
    enetRequire(pair.end[0].terminal_calls == 1 && pair.end[0].result == kEnetSessionAborted,
                "abort did not run the terminal callback before returning");
    enetRequire(pair.end[0].emitted == emitted, "abort emitted a datagram");
    enetRequire(! enetSessionIsAlive(pair.end[0].session), "an aborted session reports it is alive");
    pairSend(&pair, 0, kChunk); /* accepted and recycled */
    enetRequire(pair.end[0].emitted == emitted, "a dead session emitted a datagram");
    /* The peer learns it through ENet's timeout. */
    enetRequire(pairAdvanceUntil(&pair, 4500, serverTerminal), "the peer never noticed the abort");
    enetRequire(pair.end[1].result == kEnetSessionPeerClosed, "a vanished peer is not reported as a peer close");
    pairClose(&pair);
}

static void testQuiesceStopsCallbacks(void)
{
    static pair_t         pair;
    const enet_settings_t settings = testSettings();
    pairConnect(&pair, &settings, &settings);
    enetSessionQuiesce(pair.end[1].session);
    const unsigned emitted = pair.end[1].emitted;
    pairSend(&pair, 0, kChunk);
    pairAdvance(&pair, 100);
    enetRequire(pair.end[1].stream_length == 0 && pair.end[1].emitted == emitted,
                "a quiesced session delivered or emitted");
    /* A finish on a quiesced session cannot drain, so it aborts. */
    enetSessionAppFinish(pair.end[1].session);
    enetRequire(pair.end[1].terminal_calls == 1 && pair.end[1].result == kEnetSessionAborted,
                "a quiesced session did not abort on finish");
    pairClose(&pair);
}

int main(void)
{
    enetRuntimeStart();
    /* The nodes do this once in their constructor. */
    enetRequire(enetDriverInstall(&memoryAllocate, &memoryFree), "ENet refused the allocator");
    TEST_RUN_CASE(testHandshakeAndTransfer);
    TEST_RUN_CASE(testNestedSendKeepsOrder);
    TEST_RUN_CASE(testSendHoldFollowsAcknowledgements);
    TEST_RUN_CASE(testCarrierQueueOverflowRecovers);
    TEST_RUN_CASE(testHardCapEndsTheSender);
    TEST_RUN_CASE(testGracefulCloseDeliversFirst);
    TEST_RUN_CASE(testFinishBeforeHandshake);
    TEST_RUN_CASE(testNestedFinishKeepsQueuedBytes);
    TEST_RUN_CASE(testDrainDeadline);
    TEST_RUN_CASE(testConnectDeadlines);
    TEST_RUN_CASE(testAbortIsSilentAndSynchronous);
    TEST_RUN_CASE(testQuiesceStopsCallbacks);
    enetRuntimeStop();
    return 0;
}
