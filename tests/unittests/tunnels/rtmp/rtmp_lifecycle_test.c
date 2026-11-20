#include "RtmpClient/interface.h"

#include "RtmpServer/interface.h"
#include "fixtures/protocols/protocol_est_ordering_fixture.h"
#include "rtmp_session.h"

static uint64_t now_us = UINT64_C(1000123000);

unsigned long long __wrap_getHRTimeUs(void);
unsigned long long __wrap_getHRTimeUs(void)
{
    return now_us;
}

static void setupFixture(est_fixture_t *f, node_t *metadata, bool server)
{
    *metadata = server ? nodeRtmpServerGet() : nodeRtmpClientGet();
    twfRequire(metadata->layer_group == kNodeLayer4 && metadata->can_have_prev && metadata->can_have_next &&
                   (metadata->flags & kNodeFlagBlocksSplice) != 0 && metadata->required_padding_left == 0,
               "RTMP metadata changed its layer, adjacency, splice or padding contract");
    metadata->node_settings_json = cJSON_CreateObject();
    if (! server)
        twfRequire(cJSON_AddStringToObject(metadata->node_settings_json, "tc-url", "rtmp://localhost/waterwall") !=
                       NULL,
                   "could not set tc-url");
    tunnel_t *node = metadata->createHandle(metadata);
    twfRequire(node != NULL, "could not construct the RTMP node");

    estFixtureSetup(f, node->tstate_size, node->lstate_size);
    tunnelDestroy(f->node);
    f->node                 = node;
    f->node->chain          = f->chain;
    f->chain->workers_count = 1;
    f->prev->chain_index    = 0;
    f->node->chain_index    = 1;
    f->next->chain_index    = 2;
    tunnelBind(f->prev, f->node);
    tunnelBind(f->node, f->next);
}

static void destroyFixture(est_fixture_t *f, node_t *metadata)
{
    twfRequireLineStateZeroed(f->line, f->node, "retired RTMP line retained state");
    twfRequire(wloopNTimers(f->env.loop) == 0, "RTMP line left a live timer");
    estFixtureDestroy(f);
    cJSON_Delete(metadata->node_settings_json);
    memoryFree(metadata->type);
}

static void ownerFinish(est_fixture_t *f, line_t *line)
{
    tunnelUpStreamFin(f->node, line);
    lineDestroy(line);
}

static void carrierFinish(est_fixture_t *f, line_t *line)
{
    tunnelDownStreamFin(f->node, line);
}

static void countClientWire(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    est_fixture_t *f      = estContext(t);
    const uint32_t length = sbufGetLength(buf);
    if (f->up_len == 0)
        twfRequire(length == 1537 && sbufGetRawPtr(buf)[0] == 3, "unexpected first carrier write");
    f->up_len += length;
    lineReuseBuffer(l, buf);
    if (f->on_up != NULL)
        f->on_up(f, l);
}

static unsigned resumes;

static void countResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++resumes;
}

static void testClientUrls(void)
{
    static const struct
    {
        const char *url;
        bool        valid;
    } cases[]   = {{"rtmp://host/app", true},
                   {"rtmps://user:pass@[::1]:1935/live?token=a%20b", true},
                   {"rtmp://:1935/waterwall", false},
                   {"rtmp://user@/live", false},
                   {"rtmp://host?query/waterwall", false},
                   {"rtmp://host/#fragment", false},
                   {"rtmp://[::1/live", false},
                   {"rtmp://[name]/live", false},
                   {"rtmp://host:65536/live", false},
                   {"rtmp://host:port/live", false}};
    node_t node = nodeRtmpClientGet();
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        node.node_settings_json = cJSON_CreateObject();
        twfRequire(cJSON_AddStringToObject(node.node_settings_json, "tc-url", cases[i].url) != NULL,
                   "could not set tc-url");
        tunnel_t *t = node.createHandle(&node);
        twfRequire((t != NULL) == cases[i].valid, cases[i].url);
        if (t != NULL)
            tunnelDestroy(t);
        cJSON_Delete(node.node_settings_json);
    }
    memoryFree(node.type);
}

static void clientInit(est_fixture_t *f, line_t *l)
{
    tunnelDownStreamEst(f->node, l);
    if (! lineIsAlive(l))
        return;
    tunnelDownStreamEst(f->node, l);
    twfRequire(f->est_count == 2 && f->up_len == 0, "Est was delayed during carrier Init");
    tunnelUpStreamPayload(f->node, l, estBytes(l, "tail", 4));
}

static void testClientStartupPressure(void)
{
    est_fixture_t f;
    node_t        metadata;
    setupFixture(&f, &metadata, false);
    f.on_init          = clientInit;
    f.next->fnPayloadU = countClientWire;
    f.prev->fnPauseD   = estPause;
    f.prev->fnResumeD  = countResume;
    resumes            = 0;
    tunnelUpStreamInit(f.node, f.line);
    twfRequire(f.init_count == 1 && f.up_len == 1537 && f.est_count == 2, "client started carrier incorrectly");
    twfRequire(f.pause_count == 1 && resumes == 0, "retained startup bytes did not hold the application producer");
    twfRequire(wloopNTimers(f.env.loop) == 1, "client setup timer is missing");

    tunnelDownStreamPause(f.node, f.line);
    tunnelDownStreamPause(f.node, f.line);
    tunnelDownStreamResume(f.node, f.line);
    tunnelDownStreamEst(f.node, f.line);
    twfRequire(f.pause_count == 1 && resumes == 0, "carrier signals cleared the local hold");
    twfRequire(f.est_count == 3 && f.up_len == 1537 && wloopNTimers(f.env.loop) == 1,
               "repeated Est restarted RTMP startup");

    ownerFinish(&f, f.line);
    twfRequire(f.up_finish_count == 1 && f.down_finish_count == 0 && resumes == 0 && f.up_len == 1537 &&
                   ! lineShouldLingerOnClose(f.line),
               "explicit Finish did not cancel the retained tail");
    destroyFixture(&f, &metadata);
}

static void testClientFinishFromEst(void)
{
    est_fixture_t f;
    node_t        metadata;
    setupFixture(&f, &metadata, false);
    f.on_init          = clientInit;
    f.on_est           = ownerFinish;
    f.next->fnPayloadU = countClientWire;
    tunnelUpStreamInit(f.node, f.line);
    twfRequire(f.est_count == 1 && f.up_len == 0, "client resumed startup after its line closed from Est");
    twfRequire(f.up_finish_count == 1 && f.down_finish_count == 0, "Finish went back toward the owner");
    destroyFixture(&f, &metadata);
}

static void testClientFinishFromCarrierPayload(void)
{
    est_fixture_t f;
    node_t        metadata;
    setupFixture(&f, &metadata, false);
    f.next->fnPayloadU = countClientWire;
    f.on_up            = carrierFinish;
    tunnelUpStreamInit(f.node, f.line);
    twfRequire(f.init_count == 1 && f.up_len == 1537 && ! lineIsAlive(f.line),
               "borrowed session survived close from a carrier callback");
    twfRequire(f.up_finish_count == 0 && f.down_finish_count == 1, "Finish went back toward the carrier");
    destroyFixture(&f, &metadata);
}

static void testServerDelayedInit(void)
{
    est_fixture_t f;
    node_t        metadata;
    setupFixture(&f, &metadata, true);
    tunnelUpStreamInit(f.node, f.line);
    const uint8_t fragment[] = {3, 0, 0};
    tunnelUpStreamPayload(f.node, f.line, estBytes(f.line, fragment, sizeof(fragment)));
    twfRequire(f.init_count == 0 && f.est_count == 0 && f.up_len == 0 && f.down_len == 0,
               "incomplete handshake admitted the backend");
    twfRequire(wloopNTimers(f.env.loop) == 1, "server setup timer is missing");
    ownerFinish(&f, f.line);
    twfRequire(f.up_finish_count == 0 && f.down_finish_count == 0, "Finish reached an unadmitted backend or owner");
    destroyFixture(&f, &metadata);
}

typedef struct rtmp_peer_fixture_s
{
    est_fixture_t   flow;
    rtmp_session_t *peer;
    bool            in_backend_init;
} rtmp_peer_fixture_t;

static const uint8_t backend_banner[] = {0, '@', 's', 'e', 't', 0xfe, 0xff};

static void capturePeerInput(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    rtmp_peer_fixture_t *f = (rtmp_peer_fixture_t *) estContext(t);
    twfRequire(! f->in_backend_init, "server emitted acceptance or data inside backend Init");
    twfRequire(rtmpSessionQueueCarrier(f->peer, sbufGetRawPtr(buf), sbufGetLength(buf)),
               "could not queue wire output at the peer");
    lineReuseBuffer(l, buf);
}

/* Run the peer and deliver its wire output to the node in the carrier direction. */
static void exchangeWithPeer(rtmp_peer_fixture_t *fixture, TunnelFlowRoutinePayload receive_wire)
{
    est_fixture_t *f = &fixture->flow;
    for (unsigned step = 0; step < 128; ++step)
    {
        bool progress;
        twfRequire(rtmpSessionStep(fixture->peer, step, &progress), "peer rejected wire input");
        if (rtmpSessionPublishPending(fixture->peer))
            twfRequire(rtmpSessionAccept(fixture->peer), "server peer could not accept publication");
        uint8_t wire[RTMP_SESSION_WIRE_MAX];
        size_t  length;
        while ((length = rtmpSessionTakeWire(fixture->peer, wire, sizeof(wire), NULL)) != 0)
        {
            receive_wire(f->node, f->line, estBytes(f->line, wire, length));
            if (! lineIsAlive(f->line))
                return;
            progress = true;
        }
        if (! progress)
            return;
    }
    twfRequire(false, "RTMP peers did not finish exchanging wire output");
}

static void pauseAfterDecodedPayload(est_fixture_t *f, line_t *l)
{
    f->on_down = NULL;
    tunnelUpStreamPause(f->node, l);
}

static void testClientApplicationPause(void)
{
    rtmp_peer_fixture_t fixture = {0};
    est_fixture_t      *f       = &fixture.flow;
    node_t              metadata;
    setupFixture(f, &metadata, false);
    fixture.peer = rtmpSessionCreate(true, "waterwall", "tunnel", NULL, 1024);
    twfRequire(fixture.peer != NULL, "could not create server peer");
    f->next->fnPayloadU = capturePeerInput;
    f->next->fnResumeU  = countResume;
    resumes             = 0;
    tunnelUpStreamInit(f->node, f->line);
    tunnelDownStreamEst(f->node, f->line);
    exchangeWithPeer(&fixture, tunnelDownStreamPayload);
    twfRequire(rtmpSessionIsActive(fixture.peer) && ! wloopNTimers(f->env.loop), "client did not reach active state");

    const uint8_t upload  = 0xfe;
    const uint8_t reply[] = {0x00, 0xff};
    tunnelUpStreamPause(f->node, f->line);
    tunnelUpStreamPayload(f->node, f->line, estBytes(f->line, &upload, 1));
    for (size_t i = 0; i < sizeof(reply); ++i)
        twfRequire(rtmpSessionQueuePlain(fixture.peer, reply + i, 1), "could not queue in-flight peer replies");
    exchangeWithPeer(&fixture, tunnelDownStreamPayload);
    uint8_t received;
    twfRequire(rtmpSessionTakePlain(fixture.peer, &received, 1) == 1 && received == upload,
               "client failed to send application bytes with available credit");
    twfRequire(f->pause_count == 1 && resumes == 0 && f->down_len == 0,
               "a sendable upload released the carrier hold or delivered paused application bytes");

    f->on_down = pauseAfterDecodedPayload;
    tunnelUpStreamResume(f->node, f->line);
    twfRequire(f->down_len == 1 && f->down[0] == reply[0] && f->pause_count == 2 && resumes == 1,
               "client failed to honor application Pause from inside the first decoded payload");
    tunnelUpStreamResume(f->node, f->line);
    twfRequire(resumes == 2 && f->down_len == sizeof(reply) && memcmp(f->down, reply, sizeof(reply)) == 0,
               "client failed to release the remaining decoded bytes in order");
    ownerFinish(f, f->line);
    twfRequire(f->up_finish_count == 1 && f->down_finish_count == 0 && ! lineShouldLingerOnClose(f->line),
               "client application Finish must close only the carrier using its ordinary policy");
    rtmpSessionDestroy(fixture.peer);
    destroyFixture(f, &metadata);
}

static void injectEmptyCarrierPayload(est_fixture_t *f, line_t *l)
{
    const uint8_t unused = 0;
    tunnelUpStreamPayload(f->node, l, estBytes(l, &unused, 0));
}

static void initSynchronousBackend(est_fixture_t *f, line_t *l)
{
    rtmp_peer_fixture_t *startup = (rtmp_peer_fixture_t *) f;
    startup->in_backend_init     = true;
    twfRequire(f->init_count == 1 && f->est_count == 0, "server entered backend twice or after transport Est");
    tunnelDownStreamEst(f->node, l);
    tunnelDownStreamEst(f->node, l);
    twfRequire(f->est_count == 2, "server did not promptly forward synchronous backend Est");
    twfRequire(f->pause_count == 0, "nested carrier input sent Pause before backend Init returned");
    tunnelDownStreamPayload(f->node, l, estBytes(l, backend_banner, sizeof(backend_banner)));
    startup->in_backend_init = false;
}

static void initServer(rtmp_peer_fixture_t *startup, node_t *metadata, est_inject_fn on_init)
{
    est_fixture_t *f = &startup->flow;
    setupFixture(f, metadata, true);
    startup->peer            = rtmpSessionCreate(false, "waterwall", "tunnel", "rtmp://localhost/waterwall", 1024);
    startup->in_backend_init = false;
    twfRequire(startup->peer != NULL && rtmpSessionStart(startup->peer), "could not start the RTMP peer");
    f->prev->fnPayloadD = capturePeerInput;
    f->next->fnResumeU  = countResume;
    f->on_init          = on_init;
    f->on_est           = injectEmptyCarrierPayload;
    resumes             = 0;

    tunnelUpStreamInit(f->node, f->line);
    tunnelUpStreamPause(f->node, f->line);
    twfRequire(f->init_count == 0 && f->pause_count == 0, "startup pressure reached the backend before Init");
}

static void startServer(rtmp_peer_fixture_t *startup, node_t *metadata)
{
    est_fixture_t *f = &startup->flow;
    initServer(startup, metadata, initSynchronousBackend);
    exchangeWithPeer(startup, tunnelUpStreamPayload);
    uint8_t received[sizeof(backend_banner)];
    twfRequire(lineIsAlive(f->line) && rtmpSessionIsActive(startup->peer) &&
                   rtmpSessionTakePlain(startup->peer, received, sizeof(received)) == sizeof(received) &&
                   memoryCompare(received, backend_banner, sizeof(received)) == 0,
               "server did not transfer the exact backend Init banner after publication acceptance");
    twfRequire(f->pause_count == 1 && resumes == 0, "draining the local tail released the received carrier hold");
    twfRequire(wloopNTimers(f->env.loop) == 0, "active, drained server left a setup or send timer");
    tunnelUpStreamResume(f->node, f->line);
    twfRequire(resumes == 1, "clearing the received hold did not release the backend producer");
}

static void testServerSynchronousBackend(void)
{
    rtmp_peer_fixture_t startup;
    node_t              metadata;
    startServer(&startup, &metadata);
    est_fixture_t *f = &startup.flow;
    tunnelDownStreamFin(f->node, f->line);
    twfRequire(f->down_finish_count == 1 && f->up_finish_count == 0 && ! lineShouldLingerOnClose(f->line),
               "server application Finish must close only the carrier using its ordinary policy");
    rtmpSessionDestroy(startup.peer);
    destroyFixture(f, &metadata);
}

static void testServerRequestBeforeBackendEst(void)
{
    static const uint8_t request[] = {0, 0x50, 0xff};
    rtmp_peer_fixture_t  fixture;
    node_t               metadata;
    est_fixture_t       *f = &fixture.flow;
    initServer(&fixture, &metadata, NULL);
    twfRequire(rtmpSessionQueuePlain(fixture.peer, request, sizeof(request)), "could not queue the early request");
    exchangeWithPeer(&fixture, tunnelUpStreamPayload);
    twfRequire(rtmpSessionIsActive(fixture.peer) && f->init_count == 1 && f->est_count == 0 &&
                   f->up_len == sizeof(request) && memcmp(f->up, request, sizeof(request)) == 0,
               "server did not deliver the first request without a backend Est");

    twfRequire(wloopNTimers(f->env.loop) == 0, "publication kept the setup timer while waiting for backend Est");
    now_us += UINT64_C(11000000);
    discard wloopProcessEvents(f->env.loop, 0);
    twfRequire(lineIsAlive(f->line), "server expired an active session without a backend Est");
    tunnelUpStreamResume(f->node, f->line);
    tunnelDownStreamPayload(f->node, f->line, estBytes(f->line, backend_banner, sizeof(backend_banner)));
    exchangeWithPeer(&fixture, tunnelUpStreamPayload);
    uint8_t reply[sizeof(backend_banner)];
    twfRequire(rtmpSessionTakePlain(fixture.peer, reply, sizeof(reply)) == sizeof(reply) &&
                   memcmp(reply, backend_banner, sizeof(reply)) == 0,
               "server waited for backend Est before sending its response");

    tunnelDownStreamEst(f->node, f->line);
    tunnelDownStreamEst(f->node, f->line);
    exchangeWithPeer(&fixture, tunnelUpStreamPayload);
    twfRequire(lineIsAlive(f->line) && f->est_count == 2 && f->init_count == 1 && f->up_len == sizeof(request) &&
                   rtmpSessionIsActive(fixture.peer) && wloopNTimers(f->env.loop) == 0,
               "late or repeated Est restarted the publication or lost a transport notification");
    ownerFinish(f, f->line);
    rtmpSessionDestroy(fixture.peer);
    destroyFixture(f, &metadata);
}

static void testServerFinishFromBackendInit(void)
{
    rtmp_peer_fixture_t fixture;
    node_t              metadata;
    est_fixture_t      *f = &fixture.flow;
    initServer(&fixture, &metadata, carrierFinish);
    exchangeWithPeer(&fixture, tunnelUpStreamPayload);

    bool progress;
    do
    {
        twfRequire(rtmpSessionStep(fixture.peer, 0, &progress), "peer rejected the final server output");
    } while (progress);
    twfRequire(! lineIsAlive(f->line) && ! rtmpSessionIsActive(fixture.peer) && f->init_count == 1 &&
                   f->up_finish_count == 0 && f->down_finish_count == 1,
               "server accepted a publication or reflected Finish after its backend closed during Init");
    rtmpSessionDestroy(fixture.peer);
    destroyFixture(f, &metadata);
}

static void testServerSendDeadline(void)
{
    rtmp_peer_fixture_t startup;
    node_t              metadata;
    startServer(&startup, &metadata);
    est_fixture_t       *f           = &startup.flow;
    static const uint8_t block[8192] = {0x80, 0xff};

    /* The capture peer owns incoming wire storage but now processes nothing.
     * Fill the advertised 256 KiB window, then leave an accepted local tail. */
    for (unsigned i = 0; i < 40; ++i)
    {
        tunnelDownStreamPayload(f->node, f->line, estBytes(f->line, block, sizeof(block)));
        twfRequire(lineIsAlive(f->line), "send credit or test queue failed before the stall");
    }
    twfRequire(f->pause_count == resumes + 1 && wloopNTimers(f->env.loop) == 1,
               "credit stall did not hold the producer and arm its deadline");

    now_us += UINT64_C(15000000);
    tunnelDownStreamEst(f->node, f->line);
    discard wloopProcessEvents(f->env.loop, 0);
    twfRequire(lineIsAlive(f->line), "send deadline expired early");
    now_us += UINT64_C(15001000);
    discard wloopProcessEvents(f->env.loop, 0);
    twfRequire(! lineIsAlive(f->line) && ! lineShouldLingerOnClose(f->line) && f->up_finish_count == 1 &&
                   f->down_finish_count == 1,
               "stalled send did not cancel exactly once at the original deadline");
    rtmpSessionDestroy(startup.peer);
    destroyFixture(f, &metadata);
}

static void testCarrierPressureAcrossReverseWrites(void)
{
    rtmp_peer_fixture_t startup;
    node_t              metadata;
    startServer(&startup, &metadata);
    est_fixture_t *f = &startup.flow;
    /* Count pressure towards the carrier independently of the backend's
     * own outgoing producer hold. */
    f->next->fnPauseU = f->next->fnResumeU = estFlow;
    f->prev->fnPauseD                      = estPause;
    f->prev->fnResumeD                     = countResume;
    f->pause_count = resumes = 0;
    tunnelDownStreamPause(f->node, f->line);
    static const uint8_t block[8192] = {0x42};
    tunnelDownStreamPayload(f->node, f->line, estBytes(f->line, block, 1));
    twfRequire(f->pause_count == 1 && resumes == 0, "sendable reverse byte reopened paused carrier");

    for (unsigned i = 0; i < 40; ++i)
        tunnelDownStreamPayload(f->node, f->line, estBytes(f->line, block, sizeof(block)));
    twfRequire(lineIsAlive(f->line) && f->pause_count == 1 && resumes == 1,
               "blocked encoded tail did not reopen the carrier once for credit");

    static const uint8_t held[] = "incoming";
    twfRequire(rtmpSessionQueuePlain(startup.peer, held, sizeof(held)), "could not queue peer data alongside ACKs");
    size_t received = 0;
    for (unsigned step = 0; step < 1024; ++step)
    {
        bool progress;
        twfRequire(rtmpSessionStep(startup.peer, step, &progress), "credit exchange failed");
        uint8_t wire[RTMP_SESSION_WIRE_MAX];
        size_t  n;
        while ((n = rtmpSessionTakeWire(startup.peer, wire, sizeof(wire), NULL)) != 0)
        {
            tunnelUpStreamPayload(f->node, f->line, estBytes(f->line, wire, n));
            twfRequire(lineIsAlive(f->line), "server closed during credit exchange");
            progress = true;
        }
        uint8_t decoded[sizeof(block)];
        while ((n = rtmpSessionTakePlain(startup.peer, decoded, sizeof(decoded))) != 0)
        {
            twfRequire(n == (received == 0 ? 1 : sizeof(block)) && memcmp(decoded, block, n) == 0,
                       "reverse stream bytes changed");
            received += n;
            progress = true;
        }
        if (! progress)
            break;
    }
    twfRequire(received == 1 + 40 * sizeof(block) && f->pause_count == 2 && resumes == 1,
               "credit recovery did not drain the tail and restore carrier pressure");
    twfRequire(f->up_len == 0, "credit reads sent data to the paused application");
    tunnelDownStreamResume(f->node, f->line);
    twfRequire(resumes == 2 && f->up_len == sizeof(held) && memcmp(f->up, held, sizeof(held)) == 0,
               "application Resume did not release buffered receive data");
    tunnelDownStreamFin(f->node, f->line);
    rtmpSessionDestroy(startup.peer);
    destroyFixture(f, &metadata);
}

typedef enum
{
    kEofInSeparateRead,
    kEofWithFinalData,
    kPhysicalCarrierFinish,
} receive_close_t;

static void checkReceiveClose(receive_close_t close, bool finish_during_delivery)
{
    /* StreamEOF on the published message stream 1. */
    static const uint8_t eof[]  = {2, 0, 0, 0, 0, 0, 6, 4, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1};
    static const uint8_t tail[] = {0x80, 0x00, 0xff, 0x7f};
    rtmp_peer_fixture_t  startup;
    node_t               metadata;
    startServer(&startup, &metadata);
    est_fixture_t *f = &startup.flow;
    uint8_t        wire[256];
    size_t         used = 0;
    for (size_t i = 0; i < sizeof(tail); i += 2)
    {
        bool progress, data;
        twfRequire(rtmpSessionQueuePlain(startup.peer, tail + i, 2) && rtmpSessionStep(startup.peer, 1, &progress) &&
                       progress,
                   "could not encode the final application messages");
        const size_t n = rtmpSessionTakeWire(startup.peer, wire + used, sizeof(wire) - used, &data);
        twfRequire(n && data, "expected an application data chunk");
        used += n;
    }

    if (close != kEofInSeparateRead)
        tunnelDownStreamPause(f->node, f->line);
    if (finish_during_delivery)
        f->on_up = carrierFinish; /* The backend finishes inside its first final Payload. */
    if (close == kEofWithFinalData)
    {
        memcpy(wire + used, eof, sizeof(eof));
        used += sizeof(eof);
    }
    tunnelUpStreamPayload(f->node, f->line, estBytes(f->line, wire, used));
    if (close == kPhysicalCarrierFinish)
    {
        twfRequire(f->up_len == 0, "data escaped the paused backend before carrier Finish");
        ownerFinish(f, f->line);
    }
    else if (close == kEofInSeparateRead)
    {
        twfRequire(f->up_len == sizeof(tail), "application data was delayed until EOF");
        tunnelUpStreamPayload(f->node, f->line, estBytes(f->line, eof, sizeof(eof)));
    }
    const size_t expected = finish_during_delivery ? 2 : sizeof(tail);
    twfRequire(f->up_len == expected && memcmp(f->up, tail, expected) == 0,
               "decoded bytes lost, reordered, or delivered after the backend closed");
    twfRequire(! lineIsAlive(f->line) && f->up_finish_count == (unsigned) ! finish_during_delivery &&
                   f->down_finish_count == (unsigned) (close != kPhysicalCarrierFinish),
               "terminal delivery lost or reflected Finish");
    rtmpSessionDestroy(startup.peer);
    destroyFixture(f, &metadata);
}

static void testDecodedTailBeforeClose(void)
{
    checkReceiveClose(kEofInSeparateRead, false);
    checkReceiveClose(kEofWithFinalData, false);
    checkReceiveClose(kEofWithFinalData, true);
    checkReceiveClose(kPhysicalCarrierFinish, false);
    checkReceiveClose(kPhysicalCarrierFinish, true);
}

int main(void)
{
    TEST_RUN_CASE(testClientUrls);
    TEST_RUN_CASE(testClientStartupPressure);
    TEST_RUN_CASE(testClientApplicationPause);
    TEST_RUN_CASE(testClientFinishFromEst);
    TEST_RUN_CASE(testClientFinishFromCarrierPayload);
    TEST_RUN_CASE(testServerDelayedInit);
    TEST_RUN_CASE(testServerSynchronousBackend);
    TEST_RUN_CASE(testServerRequestBeforeBackendEst);
    TEST_RUN_CASE(testServerFinishFromBackendInit);
    TEST_RUN_CASE(testServerSendDeadline);
    TEST_RUN_CASE(testCarrierPressureAcrossReverseWrites);
    TEST_RUN_CASE(testDecodedTailBeforeClose);
    return 0;
}
