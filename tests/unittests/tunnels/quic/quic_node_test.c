/* Actual QUIC node constructors and registered callbacks: repeated Est/flow and eager data during Init,
 * synchronous Finish from Init/Est/wire/pressure, directional Finish, malformed
 * framing, byte/empty-entry admission, direct constructor string validation and
 * owner-worker quiescence. Real engine,
 * one borrowed normal line, tracked buffers and exact creator/reference cleanup.
 * CTest: waterwall.quic_node_unit, Debug and optimized Release/no-LTO. */

#include "quic_common.h"

#if QUIC_TEST_HAS_CLIENT
#include "QuicClient/interface.h"
#endif
#if QUIC_TEST_HAS_SERVER
#include "QuicServer/interface.h"
#endif

#include "fixtures/protocols/protocol_est_ordering_fixture.h"

static unsigned resume_count;

#if QUIC_TEST_HAS_SERVER
static void fixtureFatal(void)
{
    abortProgramNow(1);
}
#endif

static void discardWire(tunnel_t *t, line_t *l, sbuf_t *buffer)
{
    est_fixture_t *f        = estContext(t);
    bool           upstream = t == f->next;
    size_t        *count    = upstream ? &f->up_len : &f->down_len;
    *count += sbufGetLength(buffer);
    lineReuseBuffer(l, buffer);
    est_inject_fn inject = upstream ? f->on_up : f->on_down;
    if (inject != NULL)
    {
        inject(f, l);
    }
}

static void countResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++resume_count;
}

#if QUIC_TEST_HAS_SERVER
static ww_quic_settings_t settingsForRole(bool client)
{
    return (ww_quic_settings_t) {.is_client            = client,
                                 .verify               = true,
                                 .protocol             = "h3",
                                 .sni                  = "tls.integration.test",
                                 .ca_file              = QUIC_TEST_CERT,
                                 .cert_file            = QUIC_TEST_CERT,
                                 .key_file             = QUIC_TEST_KEY,
                                 .handshake_timeout_ms = 1000,
                                 .idle_timeout_ms      = 2000,
                                 .max_packet_size      = 1350,
                                 .max_buffered_bytes   = 65536,
                                 .max_buffered_buffers = 8,
                                 .receive_window_bytes = 16384,
                                 .allocate             = memoryAllocate,
                                 .deallocate           = memoryFree,
                                 .fatal                = fixtureFatal};
}
#endif

static bool roleEnabled(bool client)
{
    return client ? QUIC_TEST_HAS_CLIENT : QUIC_TEST_HAS_SERVER;
}

static void setupQuicWithBudget(est_fixture_t *f, bool client, bool stream, uint32_t max_bytes)
{
    estFixtureSetup(f, sizeof(quic_tstate_t), sizeof(quic_lstate_t));

    node_t *metadata = memoryAllocateZero(sizeof(*metadata));
#if QUIC_TEST_HAS_CLIENT
    if (client)
    {
        *metadata = nodeQuicClientGet();
    }
#endif
#if QUIC_TEST_HAS_SERVER
    if (! client)
    {
        *metadata = nodeQuicServerGet();
    }
#endif
    twfRequire(metadata->createHandle != NULL, "QUIC fixture requested a disabled node");
    twfRequire(metadata->layer_group == kNodeLayer4 && metadata->can_have_prev && metadata->can_have_next &&
                   (metadata->flags & kNodeFlagBlocksSplice) != 0 && metadata->required_padding_left == 0,
               "QUIC node metadata changed its layer, adjacency, splice or padding contract");
    cJSON *json = metadata->node_settings_json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "protocol", "h3");
    cJSON_AddStringToObject(json, "carrier-mode", stream ? "stream" : "datagram");
    cJSON_AddNumberToObject(json, "handshake-timeout-ms", 1000);
    cJSON_AddNumberToObject(json, "idle-timeout-ms", 2000);
    cJSON_AddNumberToObject(json, "max-packet-size", 1350);
    cJSON_AddNumberToObject(json, "max-buffered-bytes", max_bytes);
    cJSON_AddNumberToObject(json, "max-buffered-buffers", 8);
    cJSON_AddNumberToObject(json, "receive-window-bytes", 16384);
    if (client)
    {
        cJSON_AddStringToObject(json, "sni", "tls.integration.test");
        cJSON_AddStringToObject(json, "ca-file", QUIC_TEST_CERT);
        cJSON_AddBoolToObject(json, "verify", true);
    }
    else
    {
        cJSON_AddStringToObject(json, "cert-file", QUIC_TEST_CERT);
        cJSON_AddStringToObject(json, "key-file", QUIC_TEST_KEY);
    }

    tunnel_t *node = metadata->createHandle(metadata);
    twfRequire(node != NULL, "QUIC production constructor rejected valid fixture settings");
    /* Adopt the production tunnel before Init; the fixture's pooled normal
     * line remains owned by its previous endpoint and borrowed by QUIC. */
    twfRequire(node->lstate_size == f->node->lstate_size, "QUIC constructor changed the fixture line geometry");
    tunnelDestroy(f->node);
    f->node        = node;
    f->node->chain = f->chain;
    tunnelBind(f->prev, f->node);
    tunnelBind(f->node, f->next);
    f->prev->chain_index = 0;
    f->node->chain_index = 1;
    f->next->chain_index = 2;
    f->prev->fnPauseD = f->next->fnPauseU = estPause;
    f->prev->fnResumeD = f->next->fnResumeU = countResume;
    if (client)
    {
        f->next->fnPayloadU = discardWire;
    }
    else
    {
        f->prev->fnPayloadD = discardWire;
    }
    resume_count = 0;
}

static void setupQuic(est_fixture_t *f, bool client, bool stream)
{
    setupQuicWithBudget(f, client, stream, 65536);
}

static void requireSettled(est_fixture_t *f)
{
    quic_tstate_t *state = tunnelGetState(f->node);
    twfRequireLineStateZeroed(f->line, f->node, "QUIC retired line state was not zeroed");
    twfRequire(state->workers[0] == NULL, "QUIC retired context survived in borrowed registry");
    twfRequire(wloopNTimers(f->env.loop) == 0, "QUIC retired context left an armed alarm");
}

static void destroyQuic(est_fixture_t *f)
{
    requireSettled(f);
    twfRequire(! lineIsAlive(f->line), "QUIC owner line remained logically alive");
    twfRequireEqualU32(twfLineRefCount(f->line), 1, "QUIC leaked a driver line reference");
    lineUnref(f->line);
    twfLinePoolTeardown(&f->lines);
    tunnelDestroy(f->prev);
    node_t *metadata = tunnelGetNode(f->node);
    f->node->onDestroy(f->node, NULL);
    cJSON_Delete(metadata->node_settings_json);
    memoryFree(metadata->type);
    memoryFree(metadata);
    tunnelDestroy(f->next);
    memoryFree(f->chain);
    twfWorkerEnvTeardown(&f->env);
}

static void ownerFinish(est_fixture_t *f, line_t *l)
{
    tunnelUpStreamFin(f->node, l);
    /* Logical line life is independent of this borrowed node's attachment. */
    twfRequire(lineIsAlive(l), "QUIC borrower destroyed its creator's line");
    requireSettled(f);
    lineDestroy(l);
}

static void testDirectConstructorStrings(void)
{
    const char *const invalid[] = {"{\"verbose\\u0000suffix\":false}", "{\"protocol\":\"h3\\u0000suffix\"}"};
    for (unsigned client = 0; client < 2; ++client)
    {
        if (! roleEnabled(client != 0))
        {
            continue;
        }
        est_fixture_t f;
        setupQuic(&f, client != 0, false);
        tunnelUpStreamInit(f.node, f.line);
        node_t candidate    = *tunnelGetNode(f.node);
        candidate.node_json = NULL; /* No config loader or envelope supplies validation. */
        for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
        {
            cJSON *parsed = cJSON_Parse(invalid[i]);
            twfRequire(parsed != NULL, "direct constructor fixture failed permissive parsing");
            cJSON_AddStringToObject(parsed, "sni", "tls.integration.test");
            cJSON_AddStringToObject(parsed, "ca-file", QUIC_TEST_CERT);
            cJSON_AddStringToObject(parsed, "cert-file", QUIC_TEST_CERT);
            cJSON_AddStringToObject(parsed, "key-file", QUIC_TEST_KEY);
            cJSON *copy = cJSON_Duplicate(parsed, true);
            twfRequire(copy != NULL, "direct constructor settings duplication failed");
            candidate.node_settings_json = parsed;
            twfRequire(candidate.createHandle(&candidate) == NULL, "constructor accepted malformed parsed settings");
            candidate.node_settings_json = copy;
            twfRequire(candidate.createHandle(&candidate) == NULL, "constructor accepted malformed copied settings");
            cJSON_Delete(copy);
            cJSON_Delete(parsed);
        }
        ownerFinish(&f, f.line);
        destroyQuic(&f);
    }
}

#if QUIC_TEST_HAS_CLIENT
static void backendFinish(est_fixture_t *f, line_t *l)
{
    tunnelDownStreamFin(f->node, l);
}
#endif

static void eagerInit(est_fixture_t *f, line_t *l)
{
    quic_tstate_t *state = tunnelGetState(f->node);
    if (state->client)
    {
        tunnelUpStreamPayload(f->node, l, estBytes(l, "A", 1));
    }
    else
    {
        tunnelDownStreamPayload(f->node, l, estBytes(l, "server-first", 12));
    }
    twfRequire(f->up_len == 0 && f->down_len == 0, "QUIC output reentered its active Init driver");
    tunnelDownStreamEst(f->node, l);
    tunnelDownStreamEst(f->node, l);
}

static void testInitAndSignals(void)
{
    for (unsigned client = 0; client < 2; ++client)
    {
        if (! roleEnabled(client != 0))
        {
            continue;
        }
        est_fixture_t f;
        setupQuic(&f, client != 0, false);
        f.on_init = eagerInit;
        tunnelUpStreamInit(f.node, f.line);
        twfRequire(f.init_count == 1 && f.est_count == 2, "QUIC changed Init identity or suppressed repeated Est");
        twfRequire(lineIsAlive(f.line), "QUIC eager pre-readiness data closed the line");
        twfRequire(client ? f.up_len >= 1200 && f.down_len == 0 : f.up_len == 0 && f.down_len == 0,
                   "QUIC exposed unready plaintext or required Est before handshake output");
        for (unsigned i = 0; i < 2; ++i)
        {
            tunnelUpStreamPause(f.node, f.line);
            tunnelDownStreamPause(f.node, f.line);
            tunnelUpStreamResume(f.node, f.line);
            tunnelDownStreamResume(f.node, f.line);
        }
        twfRequire(f.pause_count == 4 && resume_count == 4, "QUIC absorbed repeated advisory flow signals");
        ownerFinish(&f, f.line);
        twfRequire(f.up_finish_count == 1 && f.down_finish_count == 0, "QUIC reflected owner Finish");
        destroyQuic(&f);
    }
#if QUIC_TEST_HAS_CLIENT
    est_fixture_t f;
    setupQuic(&f, true, false);
    tunnelUpStreamInit(f.node, f.line);
    twfRequire(f.est_count == 0 && f.up_len >= 1200, "QUIC handshake output incorrectly requires transport Est");
    ownerFinish(&f, f.line);
    destroyQuic(&f);
#endif
}

#if QUIC_TEST_HAS_CLIENT
static void emitEst(est_fixture_t *f, line_t *l)
{
    tunnelDownStreamEst(f->node, l);
}

static void testReentrantFinish(void)
{
    for (unsigned cause = 0; cause < 4; ++cause)
    {
        est_fixture_t f;
        setupQuic(&f, true, false);
        if (cause == 0)
        {
            f.on_init = ownerFinish;
        }
        else if (cause == 1)
        {
            f.on_init = backendFinish;
        }
        else if (cause == 2)
        {
            f.on_init = emitEst;
            f.on_est  = ownerFinish;
        }
        else
        {
            f.on_up = ownerFinish;
        }
        tunnelUpStreamInit(f.node, f.line);
        twfRequire(! lineIsAlive(f.line), "QUIC reentrant Finish retained its owner's line");
        twfRequire(cause == 1 ? f.down_finish_count == 1 && f.up_finish_count == 0
                              : f.down_finish_count == 0 && f.up_finish_count == 1,
                   "QUIC reflected reentrant Finish or forgot admitted next Init");
        twfRequire(cause == 3 ? f.up_len >= 1200 : f.up_len == 0, "QUIC emitted wire bytes after retirement");
        destroyQuic(&f);
    }
}

static void finishFromPressure(tunnel_t *t, line_t *l)
{
    est_fixture_t *f = estContext(t);
    ++f->pause_count;
    ownerFinish(f, l);
}

static void testPressureReentry(void)
{
    est_fixture_t f;
    setupQuic(&f, true, false);
    f.prev->fnPauseD = finishFromPressure;
    tunnelUpStreamInit(f.node, f.line);
    uint8_t data[50000] = {0};
    tunnelUpStreamPayload(f.node, f.line, estBytes(f.line, data, sizeof(data)));
    twfRequire(! lineIsAlive(f.line) && f.pause_count == 1 && f.up_finish_count == 1 && f.down_finish_count == 0,
               "QUIC local pressure reentry reflected Finish or retained application state");
    destroyQuic(&f);
}
#endif

static void testMalformedCarrierAndBudgets(void)
{
    for (unsigned cause = 0; cause < 3; ++cause)
    {
        if (! roleEnabled(cause != 0))
        {
            continue;
        }
        est_fixture_t f;
        setupQuic(&f, cause != 0, cause == 0);
        tunnelUpStreamInit(f.node, f.line);
        if (cause == 0)
        {
            const uint8_t zero_frame[] = {0, 0, 0, 0};
            tunnelUpStreamPayload(f.node, f.line, estBytes(f.line, zero_frame, sizeof(zero_frame)));
        }
        else if (cause == 1)
        {
            uint8_t data[65536] = {0};
            /* Opening marker has reserved credit before a full eager payload. */
            tunnelUpStreamPayload(f.node, f.line, estBytes(f.line, data, sizeof(data)));
        }
        else
        {
            /* One entry is independently reserved for the opening marker. */
            for (unsigned i = 0; i < 8; ++i)
            {
                twfRequire(lineIsAlive(f.line), "QUIC empty-entry budget failed before its configured bound");
                tunnelUpStreamPayload(f.node, f.line, estBytes(f.line, "", 0));
            }
        }
        twfRequire(! lineIsAlive(f.line) && f.up_finish_count == 1 && f.down_finish_count == 1,
                   "QUIC malformed carrier or hard refusal did not close both admitted sides");
        destroyQuic(&f);
    }
}

static void testQuiescenceBeforeOwnerDrain(void)
{
    for (unsigned client = 0; client < 2; ++client)
    {
        if (! roleEnabled(client != 0))
        {
            continue;
        }
        est_fixture_t f;
        setupQuic(&f, client != 0, true);
        tunnelUpStreamInit(f.node, f.line);
        const uint8_t prefix[] = {0, 0};
        sbuf_t       *input    = estBytes(f.line, prefix, sizeof(prefix));
        if (client)
        {
            tunnelDownStreamPayload(f.node, f.line, input);
        }
        else
        {
            tunnelUpStreamPayload(f.node, f.line, input);
        }
        quic_tstate_t *state = tunnelGetState(f.node);
        twfRequire(wloopNTimers(f.env.loop) == 1 && state->workers[0] != NULL,
                   "QUIC active handshake has no owner alarm/registry entry");
        f.node->onQuiesceRequest(f.node, NULL);
        f.node->onWorkerQuiesce(f.node, 0, NULL);
        twfRequire(lineIsAlive(f.line) && state->workers[0] != NULL && wloopNTimers(f.env.loop) == 0,
                   "QUIC borrowed quiescence destroyed an owned line or retained alarm");
        ownerFinish(&f, f.line);
        destroyQuic(&f);
    }
}

static void testCooperativeResourcePressure(void)
{
    for (unsigned client = 0; client < 2; ++client)
    {
        if (! roleEnabled(client != 0))
        {
            continue;
        }
        for (unsigned allocation = 0; allocation < 2; ++allocation)
        {
            est_fixture_t f;
            setupQuicWithBudget(&f, client != 0, false, allocation ? 131072 : 65536);
            tunnelUpStreamInit(f.node, f.line);
            unsigned count = 0;
            while (f.pause_count == 0 && count < 8)
            {
                sbuf_t *buffer =
                    allocation ? bufferpoolGetLargeBuffer(lineGetBufferPool(f.line)) : estBytes(f.line, "x", 1);
                sbufSetLength(buffer, 1);
                *(uint8_t *) sbufGetMutablePtr(buffer) = 'x';
                if (client)
                {
                    tunnelUpStreamPayload(f.node, f.line, buffer);
                }
                else
                {
                    tunnelDownStreamPayload(f.node, f.line, buffer);
                }
                ++count;
                twfRequire(lineIsAlive(f.line), "cooperative QUIC producer hit hard refusal before resource Pause");
            }
            twfRequire(f.pause_count == 1 && count == (allocation ? 3U : 7U),
                       "QUIC did not independently pause for retained allocation charge or entry count");
            ownerFinish(&f, f.line);
            destroyQuic(&f);
        }
    }
}

#if QUIC_TEST_HAS_SERVER
static struct
{
    ww_quic_engine_t *engine;
    uint8_t           bytes[64];
    size_t            length;
    bool              application_finished;
    bool              reply_sent;
    bool              finish_carrier;
    bool              carrier_finished;
    unsigned          final_wire;
} final_peer;

static void finalPeerWire(tunnel_t *t, line_t *l, sbuf_t *buffer)
{
    est_fixture_t *f = estContext(t);
    twfRequire(ww_quic_engine_feed(final_peer.engine, sbufGetRawPtr(buffer), sbufGetLength(buffer)),
               "final-reply peer rejected a server datagram");
    lineReuseBuffer(l, buffer);
    if (final_peer.application_finished)
    {
        ++final_peer.final_wire;
        /* A still-open carrier may signal pressure while final bytes are
         * handed off. The application already sent Finish and must see none. */
        tunnelUpStreamPause(f->node, l);
        tunnelUpStreamResume(f->node, l);
        if (final_peer.finish_carrier)
        {
            final_peer.carrier_finished = true;
            tunnelUpStreamFin(f->node, l);
            /* Finish detaches the borrowed session before this outer driver
             * returns, while its owner keeps the normal line alive. */
            requireSettled(f);
            twfRequire(lineIsAlive(l), "nested carrier Finish destroyed its owner's line");
        }
    }
}

static void replyThenFinish(tunnel_t *t, line_t *l, sbuf_t *buffer)
{
    est_fixture_t *f = estContext(t);
    twfRequire(! final_peer.reply_sent && sbufGetLength(buffer) == 1 &&
                   ((const uint8_t *) sbufGetRawPtr(buffer))[0] == 'R',
               "final-reply server received wrong request or opening marker");
    lineReuseBuffer(l, buffer);
    final_peer.reply_sent = true;
    tunnelDownStreamPayload(f->node, l, estBytes(l, "final", 5));
    final_peer.application_finished = true;
    tunnelDownStreamFin(f->node, l);
}

static void pumpFinalPeer(est_fixture_t *f)
{
    twfRequire(ww_quic_engine_tick(final_peer.engine), "final-reply client alarm failed");
    ww_quic_event_t event;
    while (ww_quic_engine_peek(final_peer.engine, &event))
    {
        if (event.type == WW_QUIC_EVENT_DATAGRAM)
        {
            sbuf_t *packet = lineIsAlive(f->line) && ! final_peer.carrier_finished
                                 ? estBytes(f->line, event.data, event.length)
                                 : NULL;
            ww_quic_engine_consume(final_peer.engine);
            if (packet != NULL)
            {
                tunnelUpStreamPayload(f->node, f->line, packet);
            }
        }
        else
        {
            twfRequire(event.type != WW_QUIC_EVENT_CLOSED, "final-reply peer closed before receiving report");
            if (event.type == WW_QUIC_EVENT_PLAINTEXT)
            {
                twfRequire(event.length <= sizeof(final_peer.bytes) - final_peer.length,
                           "final-reply peer received excess application bytes");
                memoryCopy(final_peer.bytes + final_peer.length, event.data, event.length);
                final_peer.length += event.length;
            }
            ww_quic_engine_consume(final_peer.engine);
        }
    }
    discard wloopProcessEvents(f->env.loop, 0);
}

static void runNestedFinalReply(bool finish_carrier)
{
    est_fixture_t f;
    setupQuic(&f, false, false);
    memoryZero(&final_peer, sizeof(final_peer));
    final_peer.finish_carrier     = finish_carrier;
    ww_quic_settings_t settings   = settingsForRole(true);
    char               error[512] = {0};
    ww_quic_config_t  *config     = ww_quic_config_create(&settings, error, sizeof(error));
    twfRequire(config != NULL, error);
    final_peer.engine  = ww_quic_engine_create(config);
    f.prev->fnPayloadD = finalPeerWire;
    f.next->fnPayloadU = replyThenFinish;
    /* Explicit owner-thread event dispatch drives the actual QUIC alarm root. */
    atomicStoreExplicit(&f.env.loop->status, WLOOP_STATUS_RUNNING, memory_order_relaxed);
    tunnelUpStreamInit(f.node, f.line);
    twfRequire(ww_quic_engine_start(final_peer.engine), "final-reply client startup failed");
    uint64_t deadline = ww_quic_now_us() + 1000000;
    while (! ww_quic_engine_ready(final_peer.engine) && ww_quic_now_us() < deadline)
    {
        pumpFinalPeer(&f);
        wwSleepMS(1);
    }
    twfRequire(ww_quic_engine_ready(final_peer.engine), "final-reply pair never opened its sole stream");
    /* Leave ordinary pacing headroom; this checks an uncongested synchronous
     * final response, not a promise of delivery after arbitrary local Finish. */
    wwSleepMS(20);
    pumpFinalPeer(&f);
    twfRequire(ww_quic_engine_write(final_peer.engine, (const uint8_t *) "R", 1), "final request was refused");
    twfRequire(ww_quic_engine_flush(final_peer.engine), "final request flush failed");
    deadline = ww_quic_now_us() + 1000000;
    while (final_peer.length < 5 && ! final_peer.carrier_finished && ww_quic_now_us() < deadline)
    {
        pumpFinalPeer(&f);
        wwSleepMS(1);
    }
    if (finish_carrier)
    {
        twfRequire(final_peer.carrier_finished && lineIsAlive(f.line),
                   "nested carrier Finish did not retain owner authority over the normal line");
        twfRequire(f.down_finish_count == 0 && f.up_finish_count == 0,
                   "QUIC reflected Finish into an already finished application or carrier");
        requireSettled(&f);
        lineDestroy(f.line);
    }
    else
    {
        twfRequire(final_peer.length == 5 && memoryCompare(final_peer.bytes, "final", 5) == 0,
                   "nested application reply followed by Finish was discarded before wire handoff");
        twfRequire(f.down_finish_count == 1 && f.up_finish_count == 0,
                   "final wire delivery reflected Finish into the finished application");
    }
    twfRequire(final_peer.reply_sent && final_peer.final_wire > 0 && ! lineIsAlive(f.line),
               "final-reply close did not retire its borrowed association");
    twfRequire(f.pause_count == 0 && resume_count == 0,
               "final wire delivery reflected a flow signal into the finished application");
    ww_quic_engine_destroy(final_peer.engine);
    ww_quic_config_destroy(config);
    final_peer.engine = NULL;
    atomicStoreExplicit(&f.env.loop->status, WLOOP_STATUS_STOP, memory_order_relaxed);
    destroyQuic(&f);
}

static void testNestedFinalReply(void)
{
    runNestedFinalReply(false);
    runNestedFinalReply(true);
}
#endif

int main(void)
{
    TEST_RUN_CASE(testDirectConstructorStrings);
    TEST_RUN_CASE(testInitAndSignals);
#if QUIC_TEST_HAS_CLIENT
    TEST_RUN_CASE(testReentrantFinish);
    TEST_RUN_CASE(testPressureReentry);
#endif
    TEST_RUN_CASE(testMalformedCarrierAndBudgets);
    TEST_RUN_CASE(testQuiescenceBeforeOwnerDrain);
    TEST_RUN_CASE(testCooperativeResourcePressure);
#if QUIC_TEST_HAS_SERVER
    TEST_RUN_CASE(testNestedFinalReply);
#endif
    return 0;
}
