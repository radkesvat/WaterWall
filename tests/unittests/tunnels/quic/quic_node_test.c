/* Actual QUIC node constructors and registered callbacks: repeated Est/flow and eager data during Init,
 * synchronous Finish from Init/Est/wire/pressure, directional Finish, malformed
 * framing, byte/empty-entry admission, direct constructor string validation and
 * owner-worker quiescence/drain, split-line ownership, pre-readiness Finish,
 * bounded reliable close and peer Finish. Real engine, independent borrowed and
 * owned normal lines, tracked buffers and exact creator/reference cleanup.
 * CTest: waterwall.quic_node_unit, Debug and optimized Release/no-LTO. */

#include "quic_common.h"
#include "runtime.h"

#if QUIC_TEST_HAS_CLIENT
#include "QuicClient/interface.h"
#endif
#if QUIC_TEST_HAS_SERVER
#include "QuicServer/interface.h"
#endif

#include "fixtures/protocols/protocol_est_ordering_fixture.h"

static unsigned resume_count;
static line_t  *owned_line;
static bool     previous_finished;
static bool     next_finished;

static bool fixtureIsClient(est_fixture_t *f)
{
    return ((quic_tstate_t *) tunnelGetState(f->node))->client;
}

static line_t *applicationLine(est_fixture_t *f)
{
    return fixtureIsClient(f) ? f->line : owned_line;
}

static line_t *carrierLine(est_fixture_t *f)
{
    return fixtureIsClient(f) ? owned_line : f->line;
}

static void requireCallbackSide(tunnel_t *t, line_t *l)
{
    est_fixture_t *f        = estContext(t);
    bool           previous = t == f->prev;
    twfRequire(l == (previous ? f->line : owned_line), "QUIC callback crossed its exact line boundary");
    twfRequire(! (previous ? previous_finished : next_finished), "QUIC callback reflected toward a finished side");
    twfRequire(lineIsAlive(l), "QUIC callback reached a logically dead line");
}

static void fixtureInit(tunnel_t *t, line_t *l)
{
    est_fixture_t *f = estContext(t);
    twfRequire(owned_line == NULL && l != f->line, "QUIC reused the borrowed line for next Init");
    owned_line = l;
    lineRef(l); /* Observe exact owner death after synchronous Finish. */
    twfRequire(lineGetWID(l) == lineGetWID(f->line), "QUIC companion line changed worker");
    twfRequire(quicGetContext(f->node, l) == quicGetContext(f->node, f->line),
               "QUIC did not publish both association links before Init");
    estInit(t, l);
}

static void fixtureEst(tunnel_t *t, line_t *l)
{
    requireCallbackSide(t, l);
    estEst(t, l);
}

static void fixturePayload(tunnel_t *t, line_t *l, sbuf_t *buffer)
{
    requireCallbackSide(t, l);
    estPayload(t, l, buffer);
}

static void fixturePause(tunnel_t *t, line_t *l)
{
    requireCallbackSide(t, l);
    estPause(t, l);
}

static void fixtureFinish(tunnel_t *t, line_t *l)
{
    requireCallbackSide(t, l);
    est_fixture_t *f = estContext(t);
    twfRequireLineStateZeroed(l, f->node, "QUIC notified Finish before detaching exact-line state");
    if (t == f->next)
    {
        next_finished = true;
        ++f->up_finish_count;
    }
    else
    {
        previous_finished = true;
        ++f->down_finish_count;
        lineDestroy(l);
    }
}

static void fixtureFatal(void)
{
    abortProgramNow(1);
}

static void discardWire(tunnel_t *t, line_t *l, sbuf_t *buffer)
{
    requireCallbackSide(t, l);
    est_fixture_t *f        = estContext(t);
    bool           upstream = t == f->next;
    size_t        *count    = upstream ? &f->up_len : &f->down_len;
    *count += sbufGetLength(buffer);
    lineReuseBuffer(l, buffer);
    est_inject_fn inject = upstream ? f->on_up : f->on_down;
    if (inject != NULL)
    {
        if (upstream)
            f->on_up = NULL;
        else
            f->on_down = NULL;
        inject(f, l);
    }
}

static void countResume(tunnel_t *t, line_t *l)
{
    requireCallbackSide(t, l);
    ++resume_count;
}

static ww_quic_settings_t settingsForRole(bool client)
{
    return (ww_quic_settings_t) {.is_client              = client,
                                 .verify                 = true,
                                 .protocol               = "h3",
                                 .sni                    = "tls.integration.test",
                                 .ca_file                = QUIC_TEST_CERT,
                                 .cert_file              = QUIC_TEST_CERT,
                                 .key_file               = QUIC_TEST_KEY,
                                 .handshake_timeout_ms   = 1000,
                                 .idle_timeout_ms        = 2000,
                                 .close_drain_timeout_ms = 300,
                                 .max_packet_size        = 1350,
                                 .max_buffered_bytes     = 65536,
                                 .max_buffered_buffers   = 8,
                                 .receive_window_bytes   = 16384,
                                 .allocate               = memoryAllocate,
                                 .deallocate             = memoryFree,
                                 .fatal                  = fixtureFatal};
}

static bool roleEnabled(bool client)
{
    return client ? QUIC_TEST_HAS_CLIENT : QUIC_TEST_HAS_SERVER;
}

static void setupQuicWithBudget(est_fixture_t *f, bool client, bool stream, uint32_t max_bytes)
{
    estFixtureSetup(f, sizeof(quic_tstate_t), sizeof(quic_lstate_t));
    owned_line        = NULL;
    previous_finished = next_finished = false;

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
    cJSON_AddNumberToObject(json, "close-drain-timeout-ms", 300);
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
    f->prev->chain_index    = 0;
    f->node->chain_index    = 1;
    f->next->chain_index    = 2;
    f->chain->workers_count = 1;
    f->next->fnInitU        = fixtureInit;
    f->prev->fnEstD         = fixtureEst;
    f->prev->fnPayloadD = f->next->fnPayloadU = fixturePayload;
    f->prev->fnFinD = f->next->fnFinU = fixtureFinish;
    f->prev->fnPauseD = f->next->fnPauseU = fixturePause;
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
    if (owned_line != NULL)
    {
        twfRequireLineStateZeroed(owned_line, f->node, "QUIC retired owned line state was not zeroed");
        twfRequire(! lineIsAlive(owned_line), "QUIC retained an owned normal line after retirement");
    }
    twfRequire(state->workers[0] == NULL, "QUIC retired context survived in borrowed registry");
    twfRequire(wloopNTimers(f->env.loop) == 0, "QUIC retired context left an armed alarm");
}

static void destroyQuic(est_fixture_t *f)
{
    requireSettled(f);
    twfRequire(! lineIsAlive(f->line), "QUIC owner line remained logically alive");
    twfRequireEqualU32(twfLineRefCount(f->line), 1, "QUIC leaked a driver line reference");
    lineUnref(f->line);
    if (owned_line != NULL)
    {
        twfRequireEqualU32(twfLineRefCount(owned_line), 1, "QUIC leaked an owned-line reference");
        lineUnref(owned_line);
        owned_line = NULL;
    }
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
    discard l;
    previous_finished = true;
    tunnelUpStreamFin(f->node, f->line);
    /* Logical line life is independent of this borrowed node's attachment. */
    twfRequire(lineIsAlive(f->line), "QUIC borrower destroyed its creator's line");
    twfRequireLineStateZeroed(f->line, f->node, "QUIC Finish left borrowed application/carrier state attached");
    lineDestroy(f->line);
}

static void nextFinish(est_fixture_t *f, line_t *l)
{
    discard l;
    next_finished = true;
    tunnelDownStreamFin(f->node, owned_line);
    twfRequire(! lineIsAlive(owned_line), "QUIC owner returned from Finish with its exact line alive");
    twfRequireLineStateZeroed(owned_line, f->node, "QUIC owned Finish did not clear line state");
}

static void abortCarrier(est_fixture_t *f)
{
    if (fixtureIsClient(f))
    {
        if (owned_line != NULL && lineIsAlive(owned_line))
            nextFinish(f, owned_line);
    }
    else if (lineIsAlive(f->line))
    {
        ownerFinish(f, f->line);
    }
    requireSettled(f);
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
        abortCarrier(&f);
        destroyQuic(&f);
    }
}

#if QUIC_TEST_HAS_CLIENT
static void backendFinish(est_fixture_t *f, line_t *l)
{
    nextFinish(f, l);
}
#endif

static void eagerInit(est_fixture_t *f, line_t *l)
{
    quic_tstate_t *state = tunnelGetState(f->node);
    if (state->client)
    {
        tunnelUpStreamPayload(f->node, f->line, estBytes(f->line, "A", 1));
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
            tunnelDownStreamPause(f.node, owned_line);
            tunnelUpStreamResume(f.node, f.line);
            tunnelDownStreamResume(f.node, owned_line);
        }
        twfRequire(f.pause_count == 4 && resume_count == 4, "QUIC absorbed repeated advisory flow signals");
        abortCarrier(&f);
        twfRequire(client ? f.up_finish_count == 0 && f.down_finish_count == 1
                          : f.up_finish_count == 1 && f.down_finish_count == 0,
                   "QUIC reflected carrier Finish");
        destroyQuic(&f);
    }
#if QUIC_TEST_HAS_CLIENT
    est_fixture_t f;
    setupQuic(&f, true, false);
    tunnelUpStreamInit(f.node, f.line);
    twfRequire(f.est_count == 0 && f.up_len >= 1200, "QUIC handshake output incorrectly requires transport Est");
    abortCarrier(&f);
    destroyQuic(&f);
#endif
}

static void testSplitLineContexts(void)
{
    for (unsigned client = 0; client < 2; ++client)
    {
        if (! roleEnabled(client != 0))
            continue;
        for (unsigned stream = 0; stream < 2; ++stream)
            for (unsigned linger_reasons = 0; linger_reasons < 4; ++linger_reasons)
            {
                est_fixture_t f;
                setupQuic(&f, client != 0, stream != 0);
                twfRequire(addresscontextSetIpAddressPortProtocol(
                               lineGetSourceAddressContext(f.line), "127.0.0.2", 12345, IP_PROTO_TCP),
                           "source fixture address failed");
                address_context_t *destination = lineGetDestinationAddressContext(f.line);
                addresscontextDomainSetByString(destination, "fixture.example");
                addresscontextSetPort(destination, 443);
                addresscontextSetOnlyProtocol(destination, IP_PROTO_TCP);
                destination->optional_flags.detected_protocols     = kAddressContextProtocolTls;
                lineGetRoutingContext(f.line)->local_listener_port = 8443;
                lineGetRoutingContext(f.line)->peer_source_port    = 23456;
                lineAddAuthenticatedCredentials(f.line, "fixture-user", "fixture-secret");
                lineMarkFallback(f.line);
                const bool protocol_drain = (linger_reasons & kLineCloseLingerProtocolDrain) != 0;
                const bool peer_shutdown  = (linger_reasons & kLineCloseLingerPeerWriteShutdown) != 0;
                if (protocol_drain)
                    lineRequestCloseLinger(f.line, kLineCloseLingerProtocolDrain);
                if (peer_shutdown)
                    lineRequestCloseLinger(f.line, kLineCloseLingerPeerWriteShutdown);
                linePreferOrdinaryReadUpstream(f.line);
                linePreferOrdinaryReadDownstream(f.line);
                tunnelUpStreamInit(f.node, f.line);
                const address_context_t *copied = lineGetDestinationAddressContext(owned_line);
                twfRequire(lineGetSourceAddressContext(owned_line)->port == 12345 && copied->port == 443 &&
                               strcmp(copied->domain, "fixture.example") == 0 &&
                               copied->domain != destination->domain &&
                               copied->optional_flags.detected_protocols == kAddressContextProtocolTls,
                           "split QUIC line lost endpoint identity or aliased owned domain memory");
                twfRequire(copied->proto_udp == (client && ! stream) && copied->proto_tcp == (! client || stream),
                           "split QUIC line copied the wrong transport protocol");
                twfRequire(lineGetRoutingContext(owned_line)->local_listener_port == 8443 &&
                               lineGetRoutingContext(owned_line)->peer_source_port == 23456 &&
                               lineGetUserAuthCount(owned_line) == 1 &&
                               strcmp(lineGetAuthenticatedUsername(owned_line), "fixture-user") == 0 &&
                               strcmp(lineGetAuthenticatedPassword(owned_line), "fixture-secret") == 0 &&
                               lineIsFallback(owned_line) && linePrefersOrdinaryReadUpstream(owned_line) &&
                               linePrefersOrdinaryReadDownstream(owned_line),
                           "split QUIC line lost routing, authentication, fallback or read-preference context");
                twfRequire(lineHasCloseLingerReason(owned_line, kLineCloseLingerPeerWriteShutdown) == peer_shutdown &&
                               ! lineHasCloseLingerReason(owned_line, kLineCloseLingerProtocolDrain),
                           "split QUIC line copied unrelated close-linger reasons or lost peer shutdown");
                twfRequire(lineHasCloseLingerReason(f.line, kLineCloseLingerPeerWriteShutdown) == peer_shutdown &&
                               lineHasCloseLingerReason(f.line, kLineCloseLingerProtocolDrain) == protocol_drain,
                           "split QUIC line changed the source close-linger reasons");
                abortCarrier(&f);
                destroyQuic(&f);
            }
    }
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
                              : f.down_finish_count == 0 && f.up_finish_count == 0,
                   "QUIC reflected reentrant Finish or forgot admitted next Init");
        twfRequire(cause == 1 ? f.up_len == 0 : f.up_len >= 1200,
                   "QUIC handshake did not respect independent carrier lifetime");
        abortCarrier(&f);
        destroyQuic(&f);
    }
}

static void finishFromPressure(tunnel_t *t, line_t *l)
{
    requireCallbackSide(t, l);
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
    twfRequire(! lineIsAlive(f.line) && f.pause_count == 1 && f.up_finish_count == 0 && f.down_finish_count == 0,
               "QUIC local pressure reentry reflected Finish or retained application state");
    abortCarrier(&f);
    destroyQuic(&f);
}
#endif

static void testInitFinishReentryBothRoles(void)
{
    for (unsigned client = 0; client < 2; ++client)
    {
        if (! roleEnabled(client != 0))
            continue;
        for (unsigned previous = 0; previous < 2; ++previous)
        {
            est_fixture_t f;
            setupQuic(&f, client != 0, false);
            f.on_init = previous ? ownerFinish : nextFinish;
            tunnelUpStreamInit(f.node, f.line);
            bool application_finished = client == previous;
            if (application_finished)
            {
                twfRequire(! lineIsAlive(applicationLine(&f)) && lineIsAlive(carrierLine(&f)),
                           "Finish during Init mixed application and carrier lifetimes");
                twfRequire(f.up_finish_count == 0 && f.down_finish_count == 0,
                           "application Finish during Init prematurely finished its carrier");
            }
            else
            {
                twfRequire(! lineIsAlive(f.line) && ! lineIsAlive(owned_line),
                           "carrier Finish during Init retained an exact owned line");
                twfRequire(client ? f.down_finish_count == 1 && f.up_finish_count == 0
                                  : f.up_finish_count == 1 && f.down_finish_count == 0,
                           "carrier Finish during Init reflected toward its sender");
            }
            abortCarrier(&f);
            destroyQuic(&f);
        }
    }
}

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
        line_t       *carrier  = carrierLine(&f);
        sbuf_t       *input    = estBytes(carrier, prefix, sizeof(prefix));
        if (client)
        {
            tunnelDownStreamPayload(f.node, carrier, input);
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
        twfRequire(f.node->onWorkerStop != NULL, "QUIC owner has no worker drain hook");
        f.node->onWorkerStop(f.node, 0, NULL);
        twfRequire(! lineIsAlive(f.line) && ! lineIsAlive(owned_line) && f.up_finish_count == 1 &&
                       f.down_finish_count == 1,
                   "QUIC worker drain did not finish both exact line lifecycles");
        destroyQuic(&f);
    }
}

static void testCarrierResourceEntries(void)
{
    for (unsigned client = 0; client < 2; ++client)
    {
        if (! roleEnabled(client != 0))
            continue;
        for (unsigned queued = 7; queued <= 8; ++queued)
        {
            est_fixture_t f;
            setupQuic(&f, client != 0, true);
            tunnelUpStreamInit(f.node, f.line);
            quic_context_t *context = quicGetContext(f.node, f.line);
            line_t         *carrier = carrierLine(&f);
            twfRequire(quicEnter(context), "fixture could not retain the QUIC driver");
            /* Serialize nested carrier arrivals before one input is popped.
             * A partial frame then needs a separate carrier body allocation. */
            const uint8_t prefix[] = {0, 0, 0, 32, 1};
            quicSubmitCarrier(f.node, carrier, estBytes(carrier, prefix, sizeof(prefix)));
            for (unsigned i = 1; i < queued; ++i)
                quicSubmitCarrier(f.node, carrier, estBytes(carrier, "", 0));
            twfRequire(lineIsAlive(f.line) && quicInputEntries(context) == queued,
                       "carrier queue refused configured entry equality");
            twfRequire(quicFeedInput(context), "queued carrier prefix was not processed");
            if (queued == 7)
            {
                twfRequire(lineIsAlive(f.line) && context->carrier_allocations == 1 && context->active_input == NULL &&
                               quicInputEntries(context) == 7,
                           "partial carrier body lost its resource slot after active input settled");
                quicSubmitCarrier(f.node, carrier, estBytes(carrier, "", 0));
                twfRequire(lineIsAlive(f.line) && quicInputEntries(context) == 8,
                           "carrier allocation and queued entries did not admit equality");
                quicSubmitCarrier(f.node, carrier, estBytes(carrier, "", 0));
            }
            twfRequire(! lineIsAlive(f.line) && f.up_finish_count == 1 && f.down_finish_count == 1,
                       "active input or retained carrier allocation escaped the resource limit");
            quicLeave(context);
            destroyQuic(&f);
        }
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
                    tunnelDownStreamPayload(f.node, owned_line, buffer);
                }
                ++count;
                twfRequire(lineIsAlive(f.line), "cooperative QUIC producer hit hard refusal before resource Pause");
            }
            twfRequire(f.pause_count == 1 && count == (allocation ? 3U : 7U),
                       "QUIC did not independently pause for retained allocation charge or entry count");
            abortCarrier(&f);
            destroyQuic(&f);
        }
    }
}

static void carrierSignal(est_fixture_t *f, bool client, bool pause)
{
    if (client)
    {
        (pause ? tunnelDownStreamPause : tunnelDownStreamResume)(f->node, owned_line);
    }
    else
    {
        (pause ? tunnelUpStreamPause : tunnelUpStreamResume)(f->node, f->line);
    }
}

static void fillApplicationBacklog(est_fixture_t *f, bool client)
{
    /* Pause comes at three quarters of the 8 entries; the seventh still fits. */
    for (unsigned count = 0; count < 7; ++count)
    {
        sbuf_t *buffer = estBytes(f->line, "x", 1);
        if (client)
        {
            tunnelUpStreamPayload(f->node, f->line, buffer);
        }
        else
        {
            tunnelDownStreamPayload(f->node, owned_line, buffer);
        }
    }
    twfRequire(lineIsAlive(f->line), "cooperative QUIC producer hit hard refusal before resource Pause");
}

/* The application stays held while either the backlog or the carrier holds it. */
static void testCarrierFlowUnderPressure(void)
{
    for (unsigned client = 0; client < 2; ++client)
    {
        if (! roleEnabled(client != 0))
        {
            continue;
        }
        est_fixture_t f;
        setupQuic(&f, client != 0, false);
        tunnelUpStreamInit(f.node, f.line);
        fillApplicationBacklog(&f, client != 0);
        twfRequire(f.pause_count == 1 && resume_count == 0, "QUIC did not pause for its own backlog");
        carrierSignal(&f, client != 0, true);
        carrierSignal(&f, client != 0, false);
        twfRequire(f.pause_count == 1 && resume_count == 0, "carrier Resume released an application under pressure");
        abortCarrier(&f);
        destroyQuic(&f);

        setupQuic(&f, client != 0, false);
        tunnelUpStreamInit(f.node, f.line);
        carrierSignal(&f, client != 0, true);
        twfRequire(f.pause_count == 1, "carrier Pause did not reach the application");
        fillApplicationBacklog(&f, client != 0);
        twfRequire(f.pause_count == 1, "backlog pressure paused an application the carrier already holds");
        carrierSignal(&f, client != 0, false);
        twfRequire(resume_count == 0, "carrier Resume released an application under pressure");
        abortCarrier(&f);
        destroyQuic(&f);
    }
}

/* A real opposite-role engine supplies ACKs/FINs through the production node's
 * carrier callback. The wire FIFO preserves ownership until the next peer step,
 * while explicit callbacks below still exercise synchronous Finish reentry. */
static struct
{
    ww_quic_config_t *config;
    ww_quic_engine_t *engine;
    buffer_queue_t    wire;
    uint8_t           bytes[512];
    size_t            length;
    bool              peer_fin;
    bool              fin_sent;
    bool              closed;
    bool              abort_on_final_wire;
    unsigned          final_wire;
} peer;

static void finishApplication(est_fixture_t *f)
{
    if (fixtureIsClient(f))
        ownerFinish(f, f->line);
    else
        nextFinish(f, owned_line);
}

static bool applicationFinished(est_fixture_t *f)
{
    return fixtureIsClient(f) ? previous_finished : next_finished;
}

static void peerWire(tunnel_t *t, line_t *l, sbuf_t *buffer)
{
    requireCallbackSide(t, l);
    est_fixture_t *f = estContext(t);
    bufferqueuePushBack(&peer.wire, buffer);
    if (applicationFinished(f))
    {
        ++peer.final_wire;
        /* These callbacks target the still-open carrier. They must not reach
         * the already-detached application even inside its Finish stack. */
        if (fixtureIsClient(f))
        {
            tunnelDownStreamEst(f->node, l);
            tunnelDownStreamPause(f->node, l);
            tunnelDownStreamResume(f->node, l);
        }
        else
        {
            tunnelUpStreamPause(f->node, l);
            tunnelUpStreamResume(f->node, l);
        }
        if (peer.abort_on_final_wire)
        {
            abortCarrier(f);
        }
    }
}

static void setupPeer(est_fixture_t *f, bool client)
{
    setupQuic(f, client, false);
    memoryZero(&peer, sizeof(peer));
    bufferqueueInitEmpty(&peer.wire);
    ww_quic_settings_t settings   = settingsForRole(! client);
    char               error[512] = {0};
    peer.config                   = ww_quic_config_create(&settings, error, sizeof(error));
    twfRequire(peer.config != NULL, error);
    peer.engine = ww_quic_engine_create(peer.config);
    twfRequire(peer.engine != NULL, "peer engine allocation failed");
    if (client)
        f->next->fnPayloadU = peerWire;
    else
        f->prev->fnPayloadD = peerWire;
    twfRequire(ww_quic_engine_start(peer.engine), "peer engine startup failed");
    tunnelUpStreamInit(f->node, f->line);
}

static void stepPeer(est_fixture_t *f)
{
    sbuf_t *buffer;
    while ((buffer = bufferqueuePopFront(&peer.wire)) != NULL)
    {
        if (! ww_quic_engine_closed(peer.engine))
        {
            bool accepted = ww_quic_engine_feed(peer.engine, sbufGetRawPtr(buffer), sbufGetLength(buffer));
            twfRequire(accepted || ww_quic_engine_closed(peer.engine), "peer rejected a live carrier packet");
        }
        bufferpoolReuseBuffer(f->env.pool, buffer);
    }
    if (! ww_quic_engine_closed(peer.engine))
        discard ww_quic_engine_tick(peer.engine);
    ww_quic_event_t event;
    while (ww_quic_engine_peek(peer.engine, &event))
    {
        if (event.type == WW_QUIC_EVENT_DATAGRAM)
        {
            line_t *carrier = carrierLine(f);
            sbuf_t *packet  = lineIsAlive(carrier) && quicGetContext(f->node, carrier) != NULL
                                  ? estBytes(carrier, event.data, event.length)
                                  : NULL;
            ww_quic_engine_consume(peer.engine);
            if (packet != NULL)
            {
                if (fixtureIsClient(f))
                    tunnelDownStreamPayload(f->node, carrier, packet);
                else
                    tunnelUpStreamPayload(f->node, carrier, packet);
            }
            continue;
        }
        if (event.type == WW_QUIC_EVENT_PLAINTEXT)
        {
            twfRequire(event.length <= sizeof(peer.bytes) - peer.length, "peer received excess application bytes");
            memoryCopy(peer.bytes + peer.length, event.data, event.length);
            peer.length += event.length;
        }
        else if (event.type == WW_QUIC_EVENT_PEER_FIN)
        {
            twfRequire(! peer.peer_fin, "peer FIN was published twice");
            peer.peer_fin = true;
        }
        else if (event.type == WW_QUIC_EVENT_CLOSED)
        {
            peer.closed = true;
        }
        ww_quic_engine_consume(peer.engine);
    }
    if (peer.peer_fin && ! peer.fin_sent && ! ww_quic_engine_closed(peer.engine))
        peer.fin_sent = ww_quic_engine_finish(peer.engine);
    if (ww_quic_engine_peer_finished(peer.engine) && ww_quic_engine_finish_acked(peer.engine) &&
        ! ww_quic_engine_closing(peer.engine) && ! ww_quic_engine_closed(peer.engine))
        ww_quic_engine_begin_close(peer.engine);
    discard wloopProcessEvents(f->env.loop, 0);
}

static void handshakePeer(est_fixture_t *f)
{
    uint64_t deadline = ww_quic_now_us() + 1000000;
    while (ww_quic_now_us() < deadline)
    {
        stepPeer(f);
        line_t *carrier = carrierLine(f);
        if (lineIsAlive(carrier))
        {
            quic_context_t *context = quicGetContext(f->node, carrier);
            if (context != NULL && ww_quic_engine_ready(context->engine) && ww_quic_engine_ready(peer.engine))
                return;
        }
        wwSleepMS(1);
    }
    twfRequire(false, "node and real peer never opened the application stream");
}

static void waitForRetirement(est_fixture_t *f)
{
    quic_tstate_t *state    = tunnelGetState(f->node);
    uint64_t       deadline = ww_quic_now_us() + 2000000;
    uint64_t       first_deadline =
        state->workers[0] != NULL && state->workers[0]->final_flush ? state->workers[0]->final_deadline_us : 0;
    while (state->workers[0] != NULL && ww_quic_now_us() < deadline)
    {
        stepPeer(f);
        if (state->workers[0] != NULL && state->workers[0]->final_flush)
        {
            if (first_deadline == 0)
                first_deadline = state->workers[0]->final_deadline_us;
            twfRequire(state->workers[0]->final_deadline_us == first_deadline,
                       "handshake or later peer FIN extended the first close deadline");
        }
        wwSleepMS(1);
    }
    /* The final data event may already be staged on the peer when the node's
     * bounded closing interval ends. Consume it before checking exact bytes. */
    stepPeer(f);
    requireSettled(f);
}

static void destroyPeer(est_fixture_t *f)
{
    bufferqueueDestroy(&peer.wire);
    ww_quic_engine_destroy(peer.engine);
    ww_quic_config_destroy(peer.config);
    peer.engine = NULL;
    destroyQuic(f);
}

static void sendApplication(est_fixture_t *f, const char *bytes)
{
    line_t *app    = applicationLine(f);
    sbuf_t *buffer = estBytes(app, bytes, strlen(bytes));
    if (fixtureIsClient(f))
        tunnelUpStreamPayload(f->node, app, buffer);
    else
        tunnelDownStreamPayload(f->node, app, buffer);
}

static void testReliableFinalReply(void)
{
    for (unsigned client = 0; client < 2; ++client)
    {
        if (! roleEnabled(client != 0))
            continue;
        for (unsigned abort = 0; abort < 2; ++abort)
        {
            est_fixture_t f;
            setupPeer(&f, client != 0);
            handshakePeer(&f);
            peer.abort_on_final_wire = abort != 0;
            sendApplication(&f, "final");
            finishApplication(&f);
            twfRequire(! lineIsAlive(applicationLine(&f)), "application Finish did not retire its exact line");
            twfRequireLineStateZeroed(applicationLine(&f), f.node, "application state survived Finish");
            if (abort)
            {
                /* If data was emitted just before Finish, FIN still produces
                 * a final wire callback in which the carrier closes reentrantly. */
                waitForRetirement(&f);
                twfRequire(f.up_finish_count == 0 && f.down_finish_count == 0,
                           "reentrant carrier Finish reflected into an already finished endpoint");
            }
            else
            {
                twfRequire(lineIsAlive(carrierLine(&f)), "application Finish prematurely destroyed its carrier");
                waitForRetirement(&f);
                twfRequire(peer.length == 5 && memoryCompare(peer.bytes, "final", 5) == 0 && peer.peer_fin,
                           "final accepted bytes or reliable FIN did not reach the peer");
                twfRequire(ww_quic_engine_closing(peer.engine) || ww_quic_engine_closed(peer.engine),
                           "normal final reply expired before both FIN directions completed");
                twfRequire(client ? f.up_finish_count == 1 && f.down_finish_count == 0
                                  : f.up_finish_count == 0 && f.down_finish_count == 1,
                           "reliable close notified the finished application or missed carrier Finish");
            }
            twfRequire(peer.final_wire != 0 && f.pause_count == 0 && resume_count == 0 && f.est_count == 0,
                       "final wire work reflected a signal into the retired application");
            destroyPeer(&f);
        }
    }
}

static void testPeerFinish(void)
{
    for (unsigned client = 0; client < 2; ++client)
    {
        if (! roleEnabled(client != 0))
            continue;
        est_fixture_t f;
        setupPeer(&f, client != 0);
        handshakePeer(&f);
        twfRequire(ww_quic_engine_write(peer.engine, (const uint8_t *) "last", 4), "peer final write was refused");
        twfRequire(ww_quic_engine_finish(peer.engine), "peer FIN was refused");
        peer.fin_sent = true;
        waitForRetirement(&f);
        size_t   length = client ? f.down_len : f.up_len;
        uint8_t *bytes  = client ? f.down : f.up;
        twfRequire(length == 4 && memoryCompare(bytes, "last", 4) == 0,
                   "peer FIN overtook its preceding application bytes");
        twfRequire(f.up_finish_count == 1 && f.down_finish_count == 1,
                   "peer FIN did not retire application and carrier exactly once");
        twfRequire(peer.peer_fin, "peer-first close did not receive the node's reciprocal FIN");
        destroyPeer(&f);
    }
}

static void replyThenFinish(tunnel_t *t, line_t *l, sbuf_t *buffer)
{
    requireCallbackSide(t, l);
    est_fixture_t *f = estContext(t);
    twfRequire(sbufGetLength(buffer) == 1 && *(const uint8_t *) sbufGetRawPtr(buffer) == 'R',
               "nested final-reply application received the wrong request");
    lineReuseBuffer(l, buffer);
    sendApplication(f, "final");
    finishApplication(f);
}

static void testNestedFinalReply(void)
{
    for (unsigned client = 0; client < 2; ++client)
    {
        if (! roleEnabled(client != 0))
            continue;
        est_fixture_t f;
        setupPeer(&f, client != 0);
        handshakePeer(&f);
        if (client)
            f.prev->fnPayloadD = replyThenFinish;
        else
            f.next->fnPayloadU = replyThenFinish;
        twfRequire(ww_quic_engine_write(peer.engine, (const uint8_t *) "R", 1), "final request was refused");
        twfRequire(ww_quic_engine_flush(peer.engine), "final request flush failed");
        waitForRetirement(&f);
        twfRequire(peer.length == 5 && memoryCompare(peer.bytes, "final", 5) == 0 && peer.peer_fin,
                   "application Payload callback discarded its reentrant final reply and Finish");
        twfRequire(client ? f.up_finish_count == 1 && f.down_finish_count == 0
                          : f.up_finish_count == 0 && f.down_finish_count == 1,
                   "nested final reply reflected Finish to its application");
        destroyPeer(&f);
    }
}

static void testFinishBeforeReadiness(void)
{
    for (unsigned client = 0; client < 2; ++client)
    {
        if (! roleEnabled(client != 0))
            continue;
        est_fixture_t f;
        setupPeer(&f, client != 0);
        twfRequire(! ww_quic_engine_ready(peer.engine), "pre-readiness fixture already completed handshake");
        sendApplication(&f, "queued");
        finishApplication(&f);
        twfRequire(! lineIsAlive(applicationLine(&f)) && lineIsAlive(carrierLine(&f)),
                   "pre-readiness Finish did not separate application retirement from carrier drain");
        waitForRetirement(&f);
        twfRequire(peer.length == 6 && memoryCompare(peer.bytes, "queued", 6) == 0 && peer.peer_fin,
                   "pre-readiness Finish discarded previously accepted application bytes");
        destroyPeer(&f);
    }
}

static void testCloseDeadlineAndShutdown(void)
{
    for (unsigned client = 0; client < 2; ++client)
    {
        if (! roleEnabled(client != 0))
            continue;
        for (unsigned shutdown = 0; shutdown < 2; ++shutdown)
        {
            est_fixture_t f;
            setupQuic(&f, client != 0, false);
            tunnelUpStreamInit(f.node, f.line);
            sendApplication(&f, "unacknowledged");
            finishApplication(&f);
            quic_tstate_t *state = tunnelGetState(f.node);
            twfRequire(state->workers[0] != NULL && lineIsAlive(carrierLine(&f)),
                       "closing association was not retained independently of its application");
            if (shutdown)
            {
                f.node->onQuiesceRequest(f.node, NULL);
                f.node->onWorkerQuiesce(f.node, 0, NULL);
                twfRequire(wloopNTimers(f.env.loop) == 0, "quiescence retained a close timer");
                f.node->onWorkerStop(f.node, 0, NULL);
            }
            else
            {
                uint64_t started = ww_quic_now_us();
                while (state->workers[0] != NULL && ww_quic_now_us() - started < 1000000)
                {
                    discard wloopProcessEvents(f.env.loop, 0);
                    wwSleepMS(1);
                }
                twfRequire(ww_quic_now_us() - started >= 200000 && ww_quic_now_us() - started < 900000,
                           "pre-readiness close exceeded its configured 300 ms deadline");
            }
            requireSettled(&f);
            twfRequire(client ? f.up_finish_count == 1 && f.down_finish_count == 0
                              : f.up_finish_count == 0 && f.down_finish_count == 1,
                       "deadline/shutdown reflected Finish toward the retired application");
            destroyQuic(&f);
        }
    }
}

static void testClosedAdmission(void)
{
    for (unsigned client = 0; client < 2; ++client)
    {
        if (! roleEnabled(client != 0))
            continue;
        est_fixture_t f;
        setupQuic(&f, client != 0, false);
        f.node->onQuiesceRequest(f.node, NULL);
        tunnelUpStreamInit(f.node, f.line);
        twfRequire(owned_line == NULL && f.init_count == 0 && f.down_finish_count == 1,
                   "closed QUIC admission created a companion or forwarded Init");
        destroyQuic(&f);
    }
}

static void finishOnResume(tunnel_t *t, line_t *l)
{
    requireCallbackSide(t, l);
    est_fixture_t *f = estContext(t);
    ++resume_count;
    sendApplication(f, "resumed");
    finishApplication(f);
}

static void testIdleResumeFinishReentry(void)
{
    for (unsigned client = 0; client < 2; ++client)
    {
        if (! roleEnabled(client != 0))
            continue;
        est_fixture_t f;
        setupPeer(&f, client != 0);
        handshakePeer(&f);
        /* Resume is the root callback. Its application receiver submits data
         * and Finish synchronously, with no later producer event to pump them. */
        if (client)
        {
            f.prev->fnResumeD = finishOnResume;
            tunnelDownStreamResume(f.node, owned_line);
        }
        else
        {
            f.next->fnResumeU = finishOnResume;
            tunnelUpStreamResume(f.node, f.line);
        }
        twfRequire(resume_count == 1 && ! lineIsAlive(applicationLine(&f)),
                   "Resume reentry did not synchronously retire the application");
        waitForRetirement(&f);
        twfRequire(peer.length == 7 && memoryCompare(peer.bytes, "resumed", 7) == 0 && peer.peer_fin,
                   "idle Resume stranded its reentrant payload or Finish");
        destroyPeer(&f);
    }
}

int main(void)
{
    TEST_RUN_CASE(testDirectConstructorStrings);
    TEST_RUN_CASE(testInitAndSignals);
    TEST_RUN_CASE(testSplitLineContexts);
#if QUIC_TEST_HAS_CLIENT
    TEST_RUN_CASE(testReentrantFinish);
    TEST_RUN_CASE(testPressureReentry);
#endif
    TEST_RUN_CASE(testMalformedCarrierAndBudgets);
    TEST_RUN_CASE(testInitFinishReentryBothRoles);
    TEST_RUN_CASE(testQuiescenceBeforeOwnerDrain);
    TEST_RUN_CASE(testCarrierResourceEntries);
    TEST_RUN_CASE(testCooperativeResourcePressure);
    TEST_RUN_CASE(testCarrierFlowUnderPressure);
    TEST_RUN_CASE(testReliableFinalReply);
    TEST_RUN_CASE(testPeerFinish);
    TEST_RUN_CASE(testNestedFinalReply);
    TEST_RUN_CASE(testFinishBeforeReadiness);
    TEST_RUN_CASE(testCloseDeadlineAndShutdown);
    TEST_RUN_CASE(testClosedAdmission);
    TEST_RUN_CASE(testIdleResumeFinishReentry);
    return 0;
}
