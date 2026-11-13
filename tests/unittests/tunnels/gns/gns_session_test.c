/* CTest: waterwall.gns_session_unit.
 * Two GNS sessions, a client and a server, joined by a wire that the test owns: every datagram one session emits
 * is handed to the other, unless the test holds or loses it. Everything runs on the test's thread as worker 0,
 * except GameNetworkingSockets' own service thread. Covered: the handshake and the server's promotion, verified
 * transfer in both directions, echo from inside the payload callback, the send hold and its release, the hard cap,
 * the limit on unacknowledged messages that keeps a connection inside GNS's 16-bit bounds, a carrier queue that
 * refuses, graceful close with data in flight from either side, the drain and connect deadlines, abort and
 * quiesce. The library runs in real time: the cases wait with deadlines and assert no timing. */

#include "GnsCommon/port.h"
#include "GnsCommon/session.h"

#include "gns_runtime.h"

enum
{
    kWireSlots = 8192,
    kChunk     = 16384,
};

typedef struct end_s
{
    gns_session_t       *session;
    struct end_s        *other;
    sbuf_t              *wire[kWireSlots]; /* datagrams this end emitted that the other end has not been given */
    size_t               wire_count;
    uint64_t             emitted;
    size_t               sent;     /* stream bytes this end gave to its session */
    size_t               received; /* stream bytes this end got, all checked against the other end's pattern */
    uint8_t              seed;
    int                  connected_calls;
    int                  pressure_calls;
    bool                 pressured;
    bool                 terminal;
    gns_session_result_t result;
    bool                 hold; /* keep what this end emits instead of delivering it */
    bool                 lose; /* drop what this end emits */
    bool                 echo; /* send every received byte back from inside the payload callback */
} end_t;

typedef struct pair_s
{
    end_t client;
    end_t server;
} pair_t;

static uint8_t patternByte(size_t offset, uint8_t seed)
{
    return (uint8_t) (offset * 31U + seed);
}

static void endEmit(void *user, sbuf_t *packet)
{
    end_t *end = user;
    ++end->emitted;
    if (end->lose || end->wire_count == kWireSlots)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(0), packet);
        return;
    }
    end->wire[end->wire_count++] = packet;
}

static void endPayload(void *user, sbuf_t *payload)
{
    end_t         *end   = user;
    const uint8_t *bytes = sbufGetRawPtr(payload);
    const size_t   size  = sbufGetLength(payload);
    for (size_t i = 0; i < size; ++i)
    {
        gnsRequire(bytes[i] == patternByte(end->received + i, end->other->seed),
                   "received bytes differ from the bytes that were sent");
    }
    end->received += size;
    if (end->echo)
    {
        /* A call from inside a callback: the session queues it behind the call that is driving. */
        gnsSessionSend(end->session, payload);
        return;
    }
    bufferpoolReuseBuffer(getWorkerBufferPool(0), payload);
}

static void endConnected(void *user)
{
    ++((end_t *) user)->connected_calls;
}

static void endPressure(void *user, bool paused)
{
    end_t *end = user;
    gnsRequire(gnsSessionIsPressured(end->session) == paused, "the hold was not published before its callback");
    end->pressured = paused;
    ++end->pressure_calls;
}

static void endTerminal(void *user, gns_session_result_t result)
{
    end_t *end = user;
    gnsRequire(! end->terminal, "a session ended twice");
    end->terminal = true;
    end->result   = result;
}

static void endStart(end_t *end, end_t *other, bool client, const char *settings_json, uint8_t seed)
{
    gns_session_config_t config = {
        .client = client,
        .wid    = 0,
        .pool   = getWorkerBufferPool(0),
        .loop   = getWorkerLoop(0),
    };
    cJSON *json = cJSON_Parse(settings_json);
    gnsRequire(json != NULL && gnsSettingsParse(&config.settings, json, "GnsTest"), "fixture settings were refused");
    cJSON_Delete(json);
    const gns_session_callbacks_t callbacks = {
        .emit      = endEmit,
        .payload   = endPayload,
        .connected = endConnected,
        .pressure  = endPressure,
        .terminal  = endTerminal,
    };
    *end         = (end_t) {.other = other, .seed = seed};
    end->session = gnsSessionCreate(&config, &callbacks, end);
    gnsRequire(end->session != NULL, "a session was not created");
    gnsSessionStart(end->session);
}

static void endStop(end_t *end)
{
    if (! end->terminal)
    {
        gnsSessionAbort(end->session, kGnsSessionAborted);
    }
    gnsSessionRelease(end->session);
    for (size_t i = 0; i < end->wire_count; ++i)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(0), end->wire[i]);
    }
    end->wire_count = 0;
}

/* Gives the other end what this end emitted, in order. */
static void endDeliver(end_t *end)
{
    if (end->hold)
    {
        return;
    }
    const size_t count = end->wire_count;
    sbuf_t      *batch[kWireSlots];
    memoryCopy(batch, end->wire, count * sizeof(batch[0]));
    end->wire_count = 0;
    for (size_t i = 0; i < count; ++i)
    {
        gnsSessionInput(end->other->session, batch[i]);
    }
}

static void pairStep(pair_t *pair)
{
    gnsTestStep();
    endDeliver(&pair->client);
    endDeliver(&pair->server);
}

#define pairUntil(pair, condition, message)                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        const uint64_t pair_deadline = gnsTestNowMs() + kGnsTestDeadlineMs;                                            \
        while (! (condition))                                                                                          \
        {                                                                                                              \
            gnsRequire(gnsTestNowMs() < pair_deadline, message);                                                       \
            pairStep(pair);                                                                                            \
            wwSleepMS(1);                                                                                              \
        }                                                                                                              \
    } while (0)

static void pairStart(pair_t *pair, const char *client_settings, const char *server_settings)
{
    endStart(&pair->client, &pair->server, true, client_settings, 7);
    endStart(&pair->server, &pair->client, false, server_settings, 91);
}

static void pairStop(pair_t *pair)
{
    endStop(&pair->client);
    endStop(&pair->server);
    /* Wakes that were on their way to the sessions find them gone. */
    for (int i = 0; i < 5; ++i)
    {
        gnsTestStep();
    }
}

static void pairConnect(pair_t *pair)
{
    pairUntil(pair,
              gnsSessionIsConnected(pair->client.session) && gnsSessionIsConnected(pair->server.session),
              "the handshake did not finish");
    gnsRequire(pair->server.connected_calls == 1 && pair->client.connected_calls == 1,
               "the end of the handshake was not reported exactly once");
}

/* Hands size bytes of this end's pattern to its session, in chunks. */
static void endSend(end_t *end, size_t size)
{
    while (size > 0 && ! end->terminal)
    {
        const size_t chunk  = min(size, (size_t) kChunk);
        sbuf_t      *buffer = bufferpoolGetBestFit(getWorkerBufferPool(0), chunk, 0);
        sbufSetLength(buffer, chunk);
        uint8_t *bytes = sbufGetMutablePtr(buffer);
        for (size_t i = 0; i < chunk; ++i)
        {
            bytes[i] = patternByte(end->sent + i, end->seed);
        }
        end->sent += chunk;
        gnsSessionSend(end->session, buffer);
        size -= chunk;
    }
}

/* Sends as a node does: it stops while the session holds it. GNS itself has no flow control. */
static void pairTransfer(pair_t *pair, end_t *from, size_t size)
{
    const size_t   target   = from->sent + size;
    const uint64_t deadline = gnsTestNowMs() + kGnsTestDeadlineMs;
    while (from->other->received < target)
    {
        gnsRequire(gnsTestNowMs() < deadline, "the transfer stopped");
        if (from->sent < target && ! gnsSessionIsPressured(from->session))
        {
            endSend(from, min(target - from->sent, (size_t) kChunk));
        }
        else
        {
            wwSleepMS(1);
        }
        pairStep(pair);
        gnsRequire(! from->terminal && ! from->other->terminal, "a session ended during a transfer");
    }
}

/* The worker loop's clock, which is the one the sessions read. */
static uint64_t loopNowMs(void)
{
    wloopUpdateTime(getWorkerLoop(0));
    return wloopNowMonotonicMS(getWorkerLoop(0));
}

static const char kFast[] = "{\"send-rate\":20000000}";
/* A liveness timeout that never comes. For the cases that keep one direction of the wire closed for as long as a
 * slow build needs, and for the close cases: a close notice that does not arrive must fail the case at its
 * deadline, not pass as a peer that timed out. */
static const char kPatient[] = "{\"send-rate\":20000000,\"no-recv-timeout-ms\":600000}";

static void caseTransferAndClose(void)
{
    pair_t pair;
    pairStart(&pair, kPatient, kPatient);
    pairConnect(&pair);
    pairTransfer(&pair, &pair.client, 512 * 1024);
    pairTransfer(&pair, &pair.server, 512 * 1024);

    /* The client finishes with its last bytes still on their way. They arrive before the server sees the close. */
    endSend(&pair.client, 96 * 1024);
    gnsSessionAppFinish(pair.client.session);
    pairUntil(&pair, pair.server.terminal, "the server never saw the client's close");
    gnsRequire(pair.server.result == kGnsSessionPeerClosed, "a peer's close was reported as something else");
    gnsRequire(pair.server.received == pair.client.sent, "bytes that were accepted before the close were lost");
    /* The closing side keeps its endpoint for a moment, to answer what was on its way, and then ends. */
    pairUntil(&pair, pair.client.terminal, "the client's close never finished");
    gnsRequire(pair.client.result == kGnsSessionClosed, "a finished local close was reported as something else");
    pairStop(&pair);
}

static void caseServerCloses(void)
{
    pair_t pair;
    pairStart(&pair, kPatient, kPatient);
    pairConnect(&pair);
    endSend(&pair.server, 200 * 1024);
    gnsSessionAppFinish(pair.server.session);
    pairUntil(&pair, pair.client.terminal, "the client never saw the server's close");
    gnsRequire(pair.client.result == kGnsSessionPeerClosed && pair.client.received == pair.server.sent,
               "the server's last bytes did not arrive before its close");
    pairUntil(&pair, pair.server.terminal, "the server's close never finished");
    gnsRequire(pair.server.result == kGnsSessionClosed, "a finished local close was reported as something else");
    pairStop(&pair);
}

static void caseEcho(void)
{
    pair_t pair;
    pairStart(&pair, kFast, kFast);
    pairConnect(&pair);
    pair.server.echo = true;
    pair.server.seed = pair.client.seed; /* the server repeats the client's bytes */
    for (int i = 0; i < 16; ++i)
    {
        endSend(&pair.client, kChunk);
        pairUntil(&pair, pair.client.received == pair.client.sent, "the echo did not come back");
    }
    gnsRequire(pair.server.received == pair.client.sent, "the server did not get what it echoed");
    pairStop(&pair);
}

/* While the peer acknowledges nothing, the producer is held above send-buffer-limit and released at half of it. */
static void casePressure(void)
{
    static const char settings[] = "{\"send-rate\":20000000,\"send-buffer-limit\":65536}";
    pair_t            pair;
    pairStart(&pair, settings, settings);
    pairConnect(&pair);
    pair.client.hold = true;
    endSend(&pair.client, 3 * kChunk);
    pairStep(&pair);
    gnsRequire(! pair.client.pressured, "the producer was held below the limit");
    /* GNS counts a few framing bytes with every message, so the fourth chunk is the one that crosses 65,536. */
    endSend(&pair.client, kChunk);
    pairUntil(&pair, pair.client.pressured, "the producer was not held above the limit");
    gnsRequire(gnsSessionOutstandingBytes(pair.client.session) > 65536, "the hold came without the bytes behind it");
    gnsRequire(! pair.client.terminal, "a payload below the hard cap ended the session");

    pair.client.hold = false;
    pairUntil(&pair, ! pair.client.pressured, "the producer was not released after the peer acknowledged");
    gnsRequire(gnsSessionOutstandingBytes(pair.client.session) <= 32768, "the hold was released above half the limit");
    gnsRequire(pair.client.pressure_calls == 2, "the hold changed more often than it had to");
    pairUntil(&pair, pair.server.received == pair.client.sent, "held bytes did not arrive after the release");
    pairStop(&pair);
}

/* A producer that ignores the hold is stopped at twice the limit, and only that session ends. */
static void caseHardCap(void)
{
    static const char settings[] = "{\"send-rate\":20000000,\"send-buffer-limit\":65536}";
    pair_t            pair;
    pairStart(&pair, settings, settings);
    pairConnect(&pair);
    pair.client.hold = true;
    endSend(&pair.client, 7 * kChunk);
    gnsRequire(! pair.client.terminal, "a payload below the cap was refused");
    /* A payload that is offered below the cap is taken whole, also when it ends above it. */
    endSend(&pair.client, kChunk);
    gnsRequire(! pair.client.terminal, "a payload that was offered below the cap was refused");
    gnsRequire(gnsSessionOutstandingBytes(pair.client.session) > 131072, "the cap was not reached");
    endSend(&pair.client, 1);
    gnsRequire(pair.client.terminal && pair.client.result == kGnsSessionCapacityFailure,
               "a payload above the cap did not end the session");
    pairStop(&pair);
}

/* GNS ends the process when one connection has 65,535 unacknowledged segments. A peer that acknowledges nothing
 * while small payloads trickle is how a connection would get there. The session holds the producer at 4,096
 * unacknowledged messages and refuses at 8,192, long before that. */
static void caseMessageLimit(void)
{
    pair_t pair;
    pairStart(&pair, kPatient, kPatient);
    pairConnect(&pair);
    pair.client.hold = true;
    for (int i = 0; i < kGnsMessagesHold; ++i)
    {
        endSend(&pair.client, 1);
    }
    pairUntil(&pair, pair.client.pressured, "thousands of unacknowledged messages did not hold the producer");
    gnsRequire(gnsSessionOutstandingBytes(pair.client.session) < 65536, "the hold was not the message limit's");
    for (int i = kGnsMessagesHold; i < kGnsMessagesHardLimit; ++i)
    {
        endSend(&pair.client, 1);
    }
    gnsRequire(! pair.client.terminal, "messages below the hard limit ended the session");
    gnsRequire(gnsSessionOutstandingMessages(pair.client.session) == kGnsMessagesHardLimit,
               "unacknowledged messages were not counted one by one");
    endSend(&pair.client, 1);
    gnsRequire(pair.client.terminal && pair.client.result == kGnsSessionCapacityFailure,
               "a message above the hard limit did not end the session");
    pairStop(&pair);
}

/* When the peer acknowledges, the messages leave the count again and the producer is released. */
static void caseMessagesAcknowledged(void)
{
    pair_t pair;
    pairStart(&pair, kPatient, kPatient);
    pairConnect(&pair);
    pair.client.hold = true;
    for (int i = 0; i < kGnsMessagesHold; ++i)
    {
        endSend(&pair.client, 1);
    }
    pairUntil(&pair, pair.client.pressured, "thousands of unacknowledged messages did not hold the producer");
    pair.client.hold = false;
    pairUntil(&pair, ! pair.client.pressured, "acknowledged messages did not release the producer");
    pairUntil(
        &pair, gnsSessionOutstandingMessages(pair.client.session) == 0, "acknowledged messages stayed in the count");
    gnsRequire(pair.server.received == kGnsMessagesHold, "small messages were lost");
    pairStop(&pair);
}

/* A carrier queue of four datagrams refuses what does not fit. GNS offers it again; nothing is lost. */
static void caseCarrierQueueRefuses(void)
{
    static const char settings[] = "{\"send-rate\":20000000,\"carrier-queue-limit\":4}";
    pair_t            pair;
    pairStart(&pair, settings, kFast);
    pairConnect(&pair);
    endSend(&pair.client, 256 * 1024);
    /* The worker does nothing for a while, so GNS's own thread finds the queue full. */
    wwSleepMS(200);
    pairUntil(&pair, pair.server.received == pair.client.sent, "data behind a full carrier queue did not arrive");
    gnsRequire(gnsSessionRefusedDatagrams(pair.client.session) > 0, "the carrier queue never refused a datagram");
    pairStop(&pair);
}

/* The peer vanishes while this side closes with data outstanding: the close ends at its fixed deadline. */
static void caseDrainTimeout(void)
{
    static const char settings[] = "{\"send-rate\":20000000,\"close-drain-timeout-ms\":400}";
    pair_t            pair;
    pairStart(&pair, settings, kFast);
    pairConnect(&pair);
    pair.client.lose = true;
    endSend(&pair.client, kChunk);
    const uint64_t begin = loopNowMs();
    gnsSessionAppFinish(pair.client.session);
    gnsRequire(gnsSessionCloseDeadline(pair.client.session) == begin + 400, "the drain deadline is not the setting's");
    pairUntil(&pair, pair.client.terminal, "a close that nobody acknowledges never ended");
    gnsRequire(pair.client.result == kGnsSessionDrainTimeout, "an unconfirmed close was reported as finished");
    gnsRequire(loopNowMs() >= begin + 400, "the drain ended before its deadline");
    pairStop(&pair);
}

/* Nothing answers. The server gives its carrier up, and the client's connection attempt ends. */
static void caseConnectTimeout(void)
{
    static const char settings[] = "{\"send-rate\":20000000,\"timeout-initial-ms\":400}";
    pair_t            pair;
    pairStart(&pair, settings, settings);
    pair.client.lose = true;
    pair.server.lose = true;
    pairUntil(&pair, pair.server.terminal && pair.client.terminal, "a handshake that cannot finish never ended");
    gnsRequire(pair.server.result == kGnsSessionConnectTimeout && pair.client.result == kGnsSessionConnectTimeout,
               "a handshake that did not finish was reported as something else");
    gnsRequire(pair.server.connected_calls == 0 && pair.client.connected_calls == 0,
               "a session without a peer reported a finished handshake");
    pairStop(&pair);
}

/* The peer stops answering after the handshake. GNS gives the connection up after no-recv-timeout-ms. */
static void caseSilentPeer(void)
{
    static const char settings[] = "{\"send-rate\":20000000,\"no-recv-timeout-ms\":500}";
    pair_t            pair;
    pairStart(&pair, settings, kFast);
    pairConnect(&pair);
    pair.server.lose = true;
    endSend(&pair.client, kChunk);
    pairUntil(&pair, pair.client.terminal, "a silent peer never ended the session");
    gnsRequire(pair.client.result == kGnsSessionPeerClosed, "a silent peer was reported as something else");
    pairStop(&pair);
}

static void caseAbortAndQuiesce(void)
{
    pair_t pair;
    pairStart(&pair, kFast, kFast);
    pairConnect(&pair);
    endSend(&pair.client, 4 * kChunk);
    const uint64_t emitted = pair.client.emitted;
    gnsSessionAbort(pair.client.session, kGnsSessionAborted);
    gnsRequire(pair.client.terminal && pair.client.result == kGnsSessionAborted, "an abort did not end the session");
    gnsRequire(pair.client.emitted == emitted, "an owner's abort emitted a datagram");
    gnsRequire(! gnsSessionIsAlive(pair.client.session), "an aborted session is still alive");

    /* A quiesced session takes no more work, and its application's Finish settles it at once. */
    gnsSessionQuiesce(pair.server.session);
    endSend(&pair.server, kChunk);
    gnsSessionAppFinish(pair.server.session);
    gnsRequire(pair.server.terminal && pair.server.result == kGnsSessionAborted,
               "a quiesced session did not settle on its application's Finish");
    pairStop(&pair);
}

static void runCases(void)
{
    TEST_RUN_CASE(caseTransferAndClose);
    TEST_RUN_CASE(caseServerCloses);
    TEST_RUN_CASE(caseEcho);
    TEST_RUN_CASE(casePressure);
    TEST_RUN_CASE(caseHardCap);
    TEST_RUN_CASE(caseMessageLimit);
    TEST_RUN_CASE(caseMessagesAcknowledged);
    TEST_RUN_CASE(caseCarrierQueueRefuses);
    TEST_RUN_CASE(caseDrainTimeout);
    TEST_RUN_CASE(caseConnectTimeout);
    TEST_RUN_CASE(caseSilentPeer);
    TEST_RUN_CASE(caseAbortAndQuiesce);
}

int main(void)
{
    gnsTestRuntimeStart();
    gnsRequire(gnsRuntimeAcquire("GnsTest"), "GameNetworkingSockets did not start");
    runCases();
    gnsRuntimeRelease();
    gnsTestRuntimeStop();
    return 0;
}
