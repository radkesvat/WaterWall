/*
 * Covers: ConnectionStripeClient and ConnectionStripeServer through their real
 * constructors and public callbacks, including the server's PipeTunnel wrapper.
 * Setup: one explicit worker, two real indexed chains, and fake transport peers
 * which preserve each lane's FIFO while allowing arbitrary inter-lane delivery.
 * Client application and server transport lines are fixture-owned normal lines;
 * client transports and the server application are owned by the tested nodes.
 * Cases: settings and malformed wire input, lane counts, fragmented/reordered
 * duplex data, server-first output and immediate close, byte/frame credit,
 * Close overtaking data, transport loss, quiescence, synchronous Resume payload
 * and rejection.
 * Checks: exact application bytes and callback targets, all owned lines dead,
 * cleared line state, balanced references, and complete buffer settlement.
 * Limits: no sockets, worker migration, or throughput claims; namespace
 * integration tests cover actual transports and multiple workers separately.
 * CTest: waterwall.connectionstripe_session_unit
 */
#include "ConnectionStripeClient/interface.h"
#include "ConnectionStripeServer/interface.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"

enum
{
    kMaxLanes        = 32,
    kCaptureCapacity = 4 * 1024 * 1024,
    kTestWindow      = 1024 * 1024,
};

typedef struct wire_piece_s
{
    struct wire_piece_s *next;
    size_t               length, consumed;
    bool                 finish;
    uint8_t              bytes[];
} wire_piece_t;

typedef struct wire_queue_s
{
    wire_piece_t *head, *tail;
} wire_queue_t;

typedef struct lane_s
{
    line_t      *client, *server;
    wire_queue_t upload, download;
    unsigned     client_finishes, server_finishes;
    size_t       upload_bytes, download_bytes;
} lane_t;

typedef struct fixture_s
{
    twf_worker_env_t env;
    tunnel_chain_t  *client_chain, *server_chain;
    node_t           client_node, server_node;
    tunnel_t        *client, *server_wrapper, *server;
    tunnel_t        *application, *client_transport, *server_transport, *backend;
    line_t          *client_main, *server_main;
    lane_t           lanes[kMaxLanes];
    unsigned         lane_count, expected_lanes;
    unsigned         backend_inits, app_established, app_finishes, backend_finishes;
    unsigned         app_pauses, app_resumes, backend_pauses, backend_resumes;
    uint8_t          upload[kCaptureCapacity], download[kCaptureCapacity];
    size_t           upload_length, download_length, server_first_length;
    bool             reject_backend_init, reject_application_est, reject_backend_payload;
    bool             reject_application_payload, server_first, finish_server_first;
    bool             application_resume_payload, backend_resume_payload, finish_resume_payload;
    bool             retire_application_during_transport_finish, retire_backend_during_transport_finish;
    bool             injected_finish;
} fixture_t;

static fixture_t f;

static void sendPattern(bool upload, size_t length, uint8_t seed);

static sbuf_t *payload(const void *bytes, size_t length)
{
    sbuf_t *buf = bufferpoolGetBestFit(f.env.pool, length, 64);
    sbufSetLength(buf, length);
    if (length != 0)
        memoryCopyLarge(sbufGetMutablePtr(buf), bytes, length);
    return buf;
}

static lane_t *findLane(line_t *line, bool client)
{
    for (unsigned i = 0; i < f.lane_count; ++i)
        if ((client ? f.lanes[i].client : f.lanes[i].server) == line)
            return &f.lanes[i];
    twfRequire(false, "callback used an unknown transport line");
    return NULL;
}

static void enqueue(wire_queue_t *queue, sbuf_t *buf, bool finish)
{
    const size_t  length = buf == NULL ? 0 : sbufGetLength(buf);
    wire_piece_t *piece  = memoryAllocateZero(sizeof(*piece) + length);
    piece->length        = length;
    piece->finish        = finish;
    if (length != 0)
    {
        twfRequire(! sbufIsSplice(buf), "striping produced nonresident wire bytes");
        memoryCopyLarge(piece->bytes, sbufGetRawPtr(buf), length);
    }
    if (queue->tail != NULL)
        queue->tail->next = piece;
    else
        queue->head = piece;
    queue->tail = piece;
    if (buf != NULL)
        bufferpoolReuseBuffer(f.env.pool, buf);
}

static void clientTransportPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    twfRequire(t == f.client_transport, "upload used the wrong transport target");
    lane_t *lane = findLane(line, true);
    lane->upload_bytes += sbufGetLength(buf);
    enqueue(&lane->upload, buf, false);
}

static void serverTransportPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    twfRequire(t == f.server_transport, "download used the wrong transport target");
    lane_t *lane = findLane(line, false);
    lane->download_bytes += sbufGetLength(buf);
    enqueue(&lane->download, buf, false);
}

static void clientTransportFinish(tunnel_t *t, line_t *line)
{
    twfRequire(t == f.client_transport, "client transport Finish reached wrong target");
    lane_t *lane = findLane(line, true);
    twfRequire(++lane->client_finishes == 1, "client transport received duplicate Finish");
    enqueue(&lane->upload, NULL, true);
    if (f.retire_application_during_transport_finish && ! f.injected_finish && lineIsAlive(f.client_main))
    {
        f.injected_finish = true;
        tunnelNextUpStreamFinish(f.application, f.client_main);
        lineDestroy(f.client_main);
    }
}

static void serverTransportFinish(tunnel_t *t, line_t *line)
{
    twfRequire(t == f.server_transport, "server transport Finish reached wrong owner");
    lane_t *lane = findLane(line, false);
    twfRequire(++lane->server_finishes == 1, "server transport received duplicate Finish");
    enqueue(&lane->download, NULL, true);
    lineDestroy(line);
    if (f.retire_backend_during_transport_finish && ! f.injected_finish && f.server_main != NULL &&
        lineIsAlive(f.server_main))
    {
        f.injected_finish = true;
        tunnelPrevDownStreamFinish(f.backend, f.server_main);
        twfRequire(! lineIsAlive(f.server_main), "reentrant backend Finish left its owned line alive");
    }
}

static void applicationFinish(tunnel_t *t, line_t *line)
{
    twfRequire(t == f.application && line == f.client_main, "application Finish used wrong line");
    ++f.app_finishes;
    lineDestroy(line);
}

static void backendFinish(tunnel_t *t, line_t *line)
{
    twfRequire(t == f.backend && line == f.server_main, "backend Finish used wrong line");
    ++f.backend_finishes;
}

static void noop(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
}

static void applicationEst(tunnel_t *t, line_t *line)
{
    twfRequire(t == f.application && line == f.client_main, "application Est used wrong line");
    ++f.app_established;
    if (f.reject_application_est)
    {
        tunnelNextUpStreamFinish(t, line);
        lineDestroy(line);
    }
}

static void backendInit(tunnel_t *t, line_t *line)
{
    twfRequire(t == f.backend && f.server_main == NULL, "session opened multiple backend connections");
    f.server_main = line;
    lineRef(line);
    ++f.backend_inits;
    if (f.reject_backend_init)
    {
        tunnelPrevDownStreamFinish(t, line);
        twfRequire(! lineIsAlive(line), "backend rejection left the owned server application alive");
        return;
    }
    tunnelPrevDownStreamEst(t, line);
    if (f.server_first && lineIsAlive(line))
    {
        if (f.server_first_length != 0)
            sendPattern(false, f.server_first_length, 211);
        else
            tunnelPrevDownStreamPayload(t, line, payload("server first", 12));
        if (f.finish_server_first)
        {
            tunnelPrevDownStreamFinish(t, line);
            twfRequire(! lineIsAlive(line), "server-first Finish returned with its owned application line alive");
        }
    }
}

static void backendPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    twfRequire(t == f.backend && line == f.server_main, "upload reached wrong application line");
    const size_t length = sbufGetLength(buf);
    twfRequire(f.upload_length + length <= sizeof(f.upload), "upload capture overflow");
    memoryCopyLarge(f.upload + f.upload_length, sbufGetRawPtr(buf), length);
    f.upload_length += length;
    lineReuseBuffer(line, buf);
    if (f.reject_backend_payload)
        tunnelPrevDownStreamFinish(t, line);
}

static void applicationPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    twfRequire(t == f.application && line == f.client_main, "download reached wrong application line");
    const size_t length = sbufGetLength(buf);
    twfRequire(f.download_length + length <= sizeof(f.download), "download capture overflow");
    memoryCopyLarge(f.download + f.download_length, sbufGetRawPtr(buf), length);
    f.download_length += length;
    lineReuseBuffer(line, buf);
    if (f.reject_application_payload)
    {
        tunnelNextUpStreamFinish(t, line);
        lineDestroy(line);
    }
}

static void applicationPause(tunnel_t *t, line_t *line)
{
    twfRequire(t == f.application && line == f.client_main, "upload producer Pause used wrong line");
    ++f.app_pauses;
}

static void applicationResume(tunnel_t *t, line_t *line)
{
    twfRequire(t == f.application && line == f.client_main, "upload producer Resume used wrong line");
    ++f.app_resumes;
    if (f.application_resume_payload)
    {
        f.application_resume_payload = false;
        tunnelNextUpStreamPayload(t, line, payload("sync", 4));
        if (f.finish_resume_payload)
        {
            tunnelNextUpStreamFinish(t, line);
            lineDestroy(line);
        }
    }
}

static void backendPause(tunnel_t *t, line_t *line)
{
    twfRequire(t == f.backend && line == f.server_main, "download producer Pause used wrong line");
    ++f.backend_pauses;
}

static void backendResume(tunnel_t *t, line_t *line)
{
    twfRequire(t == f.backend && line == f.server_main, "download producer Resume used wrong line");
    ++f.backend_resumes;
    if (f.backend_resume_payload)
    {
        f.backend_resume_payload = false;
        tunnelPrevDownStreamPayload(t, line, payload("sync", 4));
        if (f.finish_resume_payload)
        {
            tunnelPrevDownStreamFinish(t, line);
            twfRequire(! lineIsAlive(line), "Resume producer Finish left its owned application alive");
        }
    }
}

static void clientTransportInit(tunnel_t *t, line_t *line)
{
    twfRequire(t == f.client_transport && f.lane_count < f.expected_lanes, "incorrect transport fanout");
    lane_t *lane = &f.lanes[f.lane_count++];
    lane->client = line;
    lineRef(line);
    lane->server = lineCreate(tunnelchainGetLinePools(f.server_chain), 0);
    lineRef(lane->server);
    tunnelNextUpStreamInit(f.server_transport, lane->server);
    if (lineIsAlive(line))
        tunnelPrevDownStreamEst(t, line);
}

static tunnel_chain_t *makeChain(tunnel_t *entry)
{
    tunnel_chain_t *chain = tunnelchainCreate(1);
    entry->onChain(entry, chain);
    uint32_t offset = 0;
    for (unsigned i = 0; i < chain->tunnels.len; ++i)
        chain->tunnels.tuns[i]->onIndex(chain->tunnels.tuns[i], (uint16_t) i, &offset);
    twfRequire(offset == chain->sum_line_state_size, "indexed state differs from chain reservation");
    tunnelchainFinalize(chain);
    return chain;
}

static void setup(unsigned count)
{
    memoryZero(&f, sizeof(f));
    twfWorkerEnvSetup(&f.env, 64 * 1024, 64);
    f.expected_lanes   = count;
    f.client_node      = nodeConnectionStripeClientGet();
    f.server_node      = nodeConnectionStripeServerGet();
    f.client_node.name = (char *) "stripe-client";
    f.server_node.name = (char *) "stripe-server";
    f.client_node.next = f.server_node.next = (char *) "fixture-neighbor";
    f.client_node.node_settings_json        = cJSON_CreateObject();
    cJSON_AddNumberToObject(f.client_node.node_settings_json, "connections", count);
    f.client         = connectionstripeclientTunnelCreate(&f.client_node);
    f.server_wrapper = connectionstripeserverTunnelCreate(&f.server_node);
    twfRequire(f.client != NULL && f.server_wrapper != NULL, "valid stripe constructor failed");
    f.client_chain = makeChain(f.client);
    f.server_chain = makeChain(f.server_wrapper);
    f.server       = f.server_wrapper->next;
    twfRequire(f.server != NULL, "server did not insert its PipeTunnel child");

    f.application      = tunnelCreate(NULL, 0, 0);
    f.client_transport = tunnelCreate(NULL, 0, 0);
    f.server_transport = tunnelCreate(NULL, 0, 0);
    f.backend          = tunnelCreate(NULL, 0, 0);
    tunnelBind(f.application, f.client);
    tunnelBind(f.client, f.client_transport);
    tunnelBind(f.server_transport, f.server_wrapper);
    tunnelBind(f.server, f.backend);
    f.application->fnEstD          = applicationEst;
    f.application->fnPayloadD      = applicationPayload;
    f.application->fnFinD          = applicationFinish;
    f.application->fnPauseD        = applicationPause;
    f.application->fnResumeD       = applicationResume;
    f.client_transport->fnInitU    = clientTransportInit;
    f.client_transport->fnPayloadU = clientTransportPayload;
    f.client_transport->fnFinU     = clientTransportFinish;
    f.client_transport->fnPauseU = f.client_transport->fnResumeU = noop;
    f.server_transport->fnPayloadD                               = serverTransportPayload;
    f.server_transport->fnFinD                                   = serverTransportFinish;
    f.server_transport->fnEstD = f.server_transport->fnPauseD = f.server_transport->fnResumeD = noop;
    f.backend->fnInitU                                                                        = backendInit;
    f.backend->fnPayloadU                                                                     = backendPayload;
    f.backend->fnFinU                                                                         = backendFinish;
    f.backend->fnEstU                                                                         = noop;
    f.backend->fnPauseU                                                                       = backendPause;
    f.backend->fnResumeU                                                                      = backendResume;
    for (unsigned i = 0; i < f.client_chain->tunnels.len; ++i)
    {
        tunnel_t *t = f.client_chain->tunnels.tuns[i];
        t->onPrepare(t);
        t->onStart(t);
    }
    for (unsigned i = 0; i < f.server_chain->tunnels.len; ++i)
    {
        tunnel_t *t = f.server_chain->tunnels.tuns[i];
        t->onPrepare(t);
        t->onStart(t);
    }
    f.client_main = lineCreate(tunnelchainGetLinePools(f.client_chain), 0);
    lineRef(f.client_main);
}

static bool deliver(unsigned lane_index, bool upload, size_t fragment)
{
    lane_t       *lane  = &f.lanes[lane_index];
    wire_queue_t *queue = upload ? &lane->upload : &lane->download;
    wire_piece_t *piece = queue->head;
    if (piece == NULL)
        return false;
    line_t      *line   = upload ? lane->server : lane->client;
    const bool   finish = piece->finish;
    const size_t amount = min(fragment, piece->length - piece->consumed);
    sbuf_t      *buf    = ! finish && lineIsAlive(line) ? payload(piece->bytes + piece->consumed, amount) : NULL;
    piece->consumed += amount;
    if (piece->consumed == piece->length)
    {
        queue->head = piece->next;
        if (queue->head == NULL)
            queue->tail = NULL;
        memoryFree(piece);
    }
    if (! lineIsAlive(line))
        return true;
    if (finish)
    {
        if (upload)
        {
            tunnelNextUpStreamFinish(f.server_transport, line);
            lineDestroy(line);
        }
        else
            tunnelPrevDownStreamFinish(f.client_transport, line);
    }
    else if (upload)
        tunnelNextUpStreamPayload(f.server_transport, line, buf);
    else
        tunnelPrevDownStreamPayload(f.client_transport, line, buf);
    return true;
}

static void pump(size_t fragment)
{
    for (unsigned iteration = 0; iteration < 100000; ++iteration)
    {
        bool progress = false;
        for (unsigned n = f.lane_count; n != 0; --n)
        {
            progress |= deliver(n - 1, true, fragment);
            progress |= deliver(n - 1, false, fragment);
        }
        if (! progress)
            return;
    }
    twfRequire(false, "wire delivery failed to quiesce within a finite bound");
}

static void start(size_t fragment)
{
    tunnelNextUpStreamInit(f.application, f.client_main);
    twfRequire(f.lane_count == f.expected_lanes, "client did not create the requested number of transports");
    pump(fragment);
}

static void requireDead(line_t *line, tunnel_chain_t *chain)
{
    if (line == NULL)
        return;
    twfRequire(! lineIsAlive(line), "striping cleanup left a normal line alive");
    for (unsigned i = 0; i < chain->tunnels.len; ++i)
        twfRequireLineStateZeroed(line, chain->tunnels.tuns[i], "striping cleanup left line state alive");
    twfRequire(twfLineRefCount(line) == 1, "striping cleanup leaked a physical line reference");
    lineUnref(line);
}

static void teardown(void)
{
    const ww_lifecycle_context_t *context = wwLifecycleProcessShutdown();
    f.client->onQuiesceRequest(f.client, context);
    f.server->onQuiesceRequest(f.server, context);
    f.client->onWorkerStop(f.client, 0, context);
    f.server->onWorkerStop(f.server, 0, context);
    pump(SIZE_MAX);
    if (lineIsAlive(f.client_main))
    {
        tunnelNextUpStreamFinish(f.application, f.client_main);
        lineDestroy(f.client_main);
    }
    for (unsigned i = 0; i < f.lane_count; ++i)
        if (lineIsAlive(f.lanes[i].server))
        {
            tunnelNextUpStreamFinish(f.server_transport, f.lanes[i].server);
            lineDestroy(f.lanes[i].server);
        }
    pump(SIZE_MAX);
    requireDead(f.client_main, f.client_chain);
    requireDead(f.server_main, f.server_chain);
    for (unsigned i = 0; i < f.lane_count; ++i)
    {
        requireDead(f.lanes[i].client, f.client_chain);
        requireDead(f.lanes[i].server, f.server_chain);
    }
    twfRequireNoLeakedBuffers();
    f.client->onStop(f.client, context);
    f.server->onStop(f.server, context);
    f.client->onDestroy(f.client, context);
    f.server_wrapper->onDestroy(f.server_wrapper, context);
    tunnelDestroy(f.application);
    tunnelDestroy(f.client_transport);
    tunnelDestroy(f.server_transport);
    tunnelDestroy(f.backend);
    tunnelchainDestroy(f.client_chain);
    tunnelchainDestroy(f.server_chain);
    cJSON_Delete(f.client_node.node_settings_json);
    memoryFree(f.client_node.type);
    memoryFree(f.server_node.type);
    twfWorkerEnvTeardown(&f.env);
}

static void sendPattern(bool upload, size_t length, uint8_t seed)
{
    uint8_t bytes[32749];
    for (size_t offset = 0; offset < length;)
    {
        const size_t amount = min(sizeof(bytes), length - offset);
        for (size_t i = 0; i < amount; ++i)
            bytes[i] = (uint8_t) ((offset + i) * 137U + seed);
        if (upload)
            tunnelNextUpStreamPayload(f.application, f.client_main, payload(bytes, amount));
        else
            tunnelPrevDownStreamPayload(f.backend, f.server_main, payload(bytes, amount));
        offset += amount;
    }
}

static void requirePattern(bool upload, size_t length, uint8_t seed)
{
    twfRequire((upload ? f.upload_length : f.download_length) == length, "striped stream lost or duplicated bytes");
    const uint8_t *bytes = upload ? f.upload : f.download;
    for (size_t i = 0; i < length; ++i)
        twfRequire(bytes[i] == (uint8_t) (i * 137U + seed), "striped stream reordered or corrupted application bytes");
}

static void caseDuplex(unsigned lanes, size_t fragment)
{
    twfSetCase("ConnectionStripe fragmented handshake and reordered duplex stream");
    setup(lanes);
    start(fragment);
    twfRequire(f.backend_inits == 1 && f.app_established != 0, "complete group did not establish exactly one backend");
    const size_t length = 3 * kTestWindow / 4 + 179;
    sendPattern(true, length, 11);
    sendPattern(false, length, 173);
    pump(fragment);
    requirePattern(true, length, 11);
    requirePattern(false, length, 173);
    for (unsigned i = 0; i < lanes; ++i)
        twfRequire(f.lanes[i].upload_bytes > 100 && f.lanes[i].download_bytes > 100,
                   "one of the configured transports never carried application data");
    teardown();
}

static void caseServerFirst(void)
{
    twfSetCase("ConnectionStripe introductions progress without application payload");
    setup(8);
    f.server_first = true;
    start(1);
    twfRequire(f.download_length == 12 && memoryEqual(f.download, "server first", 12),
               "server-first protocol waited for application upload");
    teardown();
}

static void caseServerFirstFinishDuringInit(void)
{
    twfSetCase("ConnectionStripe preserves a complete server-first response and Finish reentering next Init");
    setup(8);
    f.server_first        = true;
    f.finish_server_first = true;
    start(1);
    twfRequire(f.download_length == 12 && memoryEqual(f.download, "server first", 12),
               "synchronous server-first Finish discarded the response while group Init was active");
    twfRequire(f.app_finishes == 1 && ! lineIsAlive(f.client_main) && ! lineIsAlive(f.server_main),
               "synchronous server-first Finish did not complete orderly response closure");
    twfRequire(f.backend_finishes == 0, "server-first close reflected Finish toward its sender");
    teardown();
}

static void caseServerFirstDataBeforeReady(void)
{
    twfSetCase("ConnectionStripe retains server-first DATA arriving on another lane before READY");
    setup(8);
    f.server_first        = true;
    f.server_first_length = 3 * 16384 + 113;
    tunnelNextUpStreamInit(f.application, f.client_main);
    twfRequire(f.lane_count == 8, "delayed READY fixture did not receive eight transports");

    /* Holding lane zero's DATA writes makes the first application record use
     * lane one, while READY still waits in lane zero's independent FIFO. */
    tunnelNextUpStreamPause(f.server_transport, f.lanes[0].server);
    for (unsigned i = 0; i < f.lane_count; ++i)
        while (deliver(i, true, SIZE_MAX))
            ;
    twfRequire(f.backend_inits == 1 && f.lanes[0].download.head != NULL && f.lanes[0].download.head->bytes[0] == 2 &&
                   f.lanes[1].download.head != NULL && f.lanes[1].download.head->bytes[0] == 3,
               "delayed READY fixture did not separate readiness and first DATA onto different lanes");
    for (unsigned i = 1; i < f.lane_count; ++i)
        while (deliver(i, false, 313))
            ;
    twfRequire(f.app_finishes == 0 && f.backend_finishes == 0 && lineIsAlive(f.client_main) &&
                   lineIsAlive(f.server_main),
               "valid server-first DATA before READY aborted the group");
    twfRequire(f.download_length == 0, "server-first DATA bypassed the READY delivery barrier");
    pump(307);
    requirePattern(false, f.server_first_length, 211);
    teardown();
}

static void caseReceiveWindow(bool upload)
{
    twfSetCase("ConnectionStripe full aggregate receive window resumes without missing-byte deadlock");
    setup(8);
    start(SIZE_MAX);
    if (upload)
        tunnelPrevDownStreamPause(f.backend, f.server_main);
    else
        tunnelNextUpStreamPause(f.application, f.client_main);
    const size_t length = 2 * kTestWindow + 113;
    sendPattern(upload, length, 37);
    pump(SIZE_MAX);
    twfRequire((upload ? f.upload_length : f.download_length) == 0, "paused application received striped payload");
    twfRequire((upload ? f.app_pauses : f.backend_pauses) != 0, "full receive window did not hold its producer");
    if (upload)
        tunnelPrevDownStreamResume(f.backend, f.server_main);
    else
        tunnelNextUpStreamResume(f.application, f.client_main);
    pump(317);
    requirePattern(upload, length, 37);
    twfRequire((upload ? f.app_resumes : f.backend_resumes) != 0,
               "returned aggregate receive credit did not release its producer");
    teardown();
}

static void caseResumePayload(bool upload, bool finish)
{
    twfSetCase(upload ? "ConnectionStripe synchronous upload Resume drains without a later event"
                      : "ConnectionStripe synchronous download Resume drains without a later event");
    setup(2);
    start(SIZE_MAX);
    const unsigned pauses  = upload ? f.app_pauses : f.backend_pauses;
    const unsigned resumes = upload ? f.app_resumes : f.backend_resumes;
    for (unsigned i = 0; i < f.lane_count; ++i)
    {
        twfRequire(f.lanes[i].upload.head == NULL && f.lanes[i].download.head == NULL,
                   "Resume fixture still has a pending wire event after setup");
        if (upload)
            tunnelPrevDownStreamPause(f.client_transport, f.lanes[i].client);
        else
            tunnelNextUpStreamPause(f.server_transport, f.lanes[i].server);
    }
    twfRequire((upload ? f.app_pauses : f.backend_pauses) == pauses + 1,
               "pausing every transport did not hold the empty producer");
    f.application_resume_payload = upload;
    f.backend_resume_payload     = ! upload;
    f.finish_resume_payload      = finish;
    if (upload)
        tunnelPrevDownStreamResume(f.client_transport, f.lanes[1].client);
    else
        tunnelNextUpStreamResume(f.server_transport, f.lanes[1].server);
    twfRequire((upload ? f.app_resumes : f.backend_resumes) == resumes + 1 && ! f.application_resume_payload &&
                   ! f.backend_resume_payload,
               "transport Resume did not synchronously restart its producer");

    /* No wire delivery or further callback is allowed to rescue a lost pump
     * request: the Resume call itself must have emitted the queued DATA. */
    wire_piece_t *data = upload ? f.lanes[1].upload.head : f.lanes[1].download.head;
    twfRequire(data != NULL && ! data->finish && data->length == 28 && data->bytes[0] == 3 &&
                   memoryEqual(data->bytes + 24, "sync", 4),
               "synchronous Resume payload stalled without a subsequent event");
    pump(SIZE_MAX);
    twfRequire((upload ? f.upload_length : f.download_length) == 4 &&
                   memoryEqual(upload ? f.upload : f.download, "sync", 4),
               "synchronous Resume payload was lost, duplicated or corrupted");
    if (finish)
        twfRequire(! lineIsAlive(f.client_main) && ! lineIsAlive(f.server_main) &&
                       (upload ? f.app_finishes : f.backend_finishes) == 0 &&
                       (upload ? f.backend_finishes : f.app_finishes) == 1,
                   "Finish inside Resume failed to drain or reflected Finish toward its sender");
    else
        twfRequire(lineIsAlive(f.client_main) && lineIsAlive(f.server_main),
                   "synchronous Resume payload unexpectedly closed the session");
    teardown();
}

static void caseTransportFailure(bool upload)
{
    twfSetCase("ConnectionStripe losing one transport closes the complete session");
    setup(8);
    start(SIZE_MAX);
    line_t *lost = upload ? f.lanes[3].server : f.lanes[3].client;
    if (upload)
    {
        tunnelNextUpStreamFinish(f.server_transport, lost);
        lineDestroy(lost);
    }
    else
        tunnelPrevDownStreamFinish(f.client_transport, lost);
    pump(SIZE_MAX);
    twfRequire(! lineIsAlive(f.client_main) && ! lineIsAlive(f.server_main),
               "unexpected transport loss left its application alive");
    twfRequire(f.app_finishes == 1 && f.backend_finishes == 1,
               "transport loss did not finish both applications exactly once");
    teardown();
}

static void caseSiblingFinishReentry(bool client)
{
    twfSetCase("ConnectionStripe sibling Finish may synchronously retire the still-published application");
    setup(8);
    start(SIZE_MAX);
    f.retire_application_during_transport_finish = client;
    f.retire_backend_during_transport_finish     = ! client;
    if (client)
        tunnelPrevDownStreamFinish(f.client_transport, f.lanes[3].client);
    else
    {
        tunnelNextUpStreamFinish(f.server_transport, f.lanes[3].server);
        lineDestroy(f.lanes[3].server);
    }
    pump(SIZE_MAX);
    twfRequire(f.injected_finish && ! lineIsAlive(f.client_main) && ! lineIsAlive(f.server_main),
               "sibling Finish did not complete reentrant application retirement");
    twfRequire((client ? f.app_finishes : f.backend_finishes) == 0,
               "outer transport cleanup reflected Finish toward the reentrantly finished application");
    teardown();
}

static void caseCloseOvertakesData(bool upload)
{
    twfSetCase("ConnectionStripe final offset prevents Close from overtaking another lane's data");
    setup(8);
    start(SIZE_MAX);
    const size_t length = 8 * 16384 + 113;
    sendPattern(upload, length, 91);
    if (upload)
    {
        tunnelNextUpStreamFinish(f.application, f.client_main);
        lineDestroy(f.client_main);
    }
    else
    {
        tunnelPrevDownStreamFinish(f.backend, f.server_main);
        twfRequire(! lineIsAlive(f.server_main), "owned backend remained alive after its Finish handler");
    }

    while (deliver(0, upload, SIZE_MAX))
        ;
    twfRequire((upload ? f.backend_finishes : f.app_finishes) == 0,
               "Close finished the destination before delayed lane data arrived");
    twfRequire(lineIsAlive(upload ? f.server_main : f.client_main),
               "Close destroyed its destination while earlier bytes remained in flight");
    pump(311);
    requirePattern(upload, length, 91);
    twfRequire((upload ? f.backend_finishes : f.app_finishes) == 1,
               "complete final offset did not finish the destination exactly once");
    teardown();
}

static void caseCloseAfterQuiesce(bool upload)
{
    twfSetCase("ConnectionStripe peer Close after worker quiescence cannot rearm a drain timer");
    setup(8);
    start(SIZE_MAX);
    tunnel_t *receiver = upload ? f.server : f.client;
    receiver->onWorkerQuiesce(receiver, 0, wwLifecycleProcessShutdown());
    if (upload)
    {
        tunnelNextUpStreamFinish(f.application, f.client_main);
        lineDestroy(f.client_main);
    }
    else
        tunnelPrevDownStreamFinish(f.backend, f.server_main);
    pump(SIZE_MAX);
    twfRequire(! lineIsAlive(f.client_main) && ! lineIsAlive(f.server_main),
               "peer Close during quiescence left its application alive");
    teardown();
}

static void caseJoinAfterQuiesce(void)
{
    twfSetCase("ConnectionStripe pending JOIN cannot create an application after server quiescence");
    setup(8);
    tunnelNextUpStreamInit(f.application, f.client_main);
    twfRequire(f.lane_count == 8 && f.backend_inits == 0,
               "quiesced JOIN fixture did not retain every introduction before backend setup");
    f.server->onWorkerQuiesce(f.server, 0, wwLifecycleProcessShutdown());
    pump(11);
    twfRequire(f.backend_inits == 0 && f.server_main == NULL && ! lineIsAlive(f.client_main),
               "late JOIN started an application or left the rejected client alive after quiescence");
    for (unsigned i = 0; i < f.lane_count; ++i)
        twfRequire(! lineIsAlive(f.lanes[i].client) && ! lineIsAlive(f.lanes[i].server),
                   "quiesced JOIN rejection did not close every transport");
    teardown();
}

static void caseDuplexReceiveWindow(void)
{
    twfSetCase("ConnectionStripe independently reopens simultaneously full upload and download windows");
    setup(8);
    start(SIZE_MAX);
    tunnelPrevDownStreamPause(f.backend, f.server_main);
    tunnelNextUpStreamPause(f.application, f.client_main);
    const size_t length = 2 * kTestWindow + 71;
    sendPattern(true, length, 13);
    sendPattern(false, length, 193);
    pump(SIZE_MAX);
    twfRequire(f.upload_length == 0 && f.download_length == 0 && f.app_pauses != 0 && f.backend_pauses != 0,
               "simultaneously full windows failed to retain both streams and hold both producers");
    tunnelPrevDownStreamResume(f.backend, f.server_main);
    pump(401);
    requirePattern(true, length, 13);
    twfRequire(f.download_length == 0, "upload Resume released the independent download hold");
    tunnelNextUpStreamResume(f.application, f.client_main);
    pump(401);
    requirePattern(false, length, 193);
    teardown();
}

static void caseFrameWindow(bool upload)
{
    twfSetCase("ConnectionStripe frame-count credit bounds many tiny out-of-order frames");
    setup(8);
    start(SIZE_MAX);
    if (upload)
        tunnelPrevDownStreamPause(f.backend, f.server_main);
    else
        tunnelNextUpStreamPause(f.application, f.client_main);
    for (unsigned i = 0; i < 511; ++i)
    {
        const uint8_t byte = (uint8_t) (i * 137U + 51U);
        if (upload)
            tunnelNextUpStreamPayload(f.application, f.client_main, payload(&byte, 1));
        else
            tunnelPrevDownStreamPayload(f.backend, f.server_main, payload(&byte, 1));
    }
    pump(7);
    twfRequire((upload ? f.app_pauses : f.backend_pauses) != 0,
               "frame-count receive credit did not bound tiny-frame retention");
    twfRequire((upload ? f.upload_length : f.download_length) == 0,
               "tiny frames bypassed application receive pressure");
    if (upload)
        tunnelPrevDownStreamResume(f.backend, f.server_main);
    else
        tunnelNextUpStreamResume(f.application, f.client_main);
    pump(7);
    requirePattern(upload, 511, 51);
    teardown();
}

static void caseInvalidJoin(unsigned mode)
{
    twfSetCase("ConnectionStripe rejects duplicate, inconsistent and malformed introductions");
    setup(8);
    tunnelNextUpStreamInit(f.application, f.client_main);
    twfRequire(f.lane_count == 8, "invalid introduction fixture did not receive eight transports");
    wire_piece_t *join = f.lanes[1].upload.head;
    twfRequire(join != NULL && join->length == 48 && join->bytes[0] == 1,
               "client introduction differs from the ConnectionStripe wire contract");
    switch (mode)
    {
    case 0:
        join->bytes[40] = join->bytes[41] = 0; /* Duplicate lane zero. */
        break;
    case 1:
        join->bytes[43] = 7; /* The same session announced a different group size. */
        break;
    case 2:
        join->bytes[41] = 8; /* Index outside the announced group. */
        break;
    case 3:
        join->bytes[43] = 33; /* Group exceeds the protocol's limit. */
        break;
    case 4:
        join->bytes[1] = 1; /* Reserved header bits. */
        break;
    case 5:
        memoryZero(join->bytes + 44, 4); /* Zero receive window. */
        break;
    default:
        twfRequire(false, "unknown malformed introduction fixture");
    }
    deliver(0, true, SIZE_MAX);
    deliver(1, true, SIZE_MAX);
    pump(SIZE_MAX);
    twfRequire(f.backend_inits == 0 && ! lineIsAlive(f.client_main),
               "invalid introduction opened an application or left its client alive");
    teardown();
}

static void caseInvalidData(unsigned mode)
{
    twfSetCase("ConnectionStripe rejects malformed DATA without delivering attacker-selected ranges");
    setup(8);
    start(SIZE_MAX);
    sendPattern(true, 16384, 23);
    wire_piece_t *data = NULL;
    for (unsigned i = 0; i < f.lane_count && data == NULL; ++i)
        if (f.lanes[i].upload.head != NULL && f.lanes[i].upload.head->bytes[0] == 3)
            data = f.lanes[i].upload.head;
    twfRequire(data != NULL && data->length == 24 + 16384, "fixture did not capture a complete DATA frame");
    switch (mode)
    {
    case 0:
        data->bytes[7] = 1; /* 16385-byte declaration exceeds the frame bound. */
        break;
    case 1:
        memorySet(data->bytes + 8, 0xFF, 8); /* Offset cannot fit the receive window. */
        break;
    case 2:
        memorySet(data->bytes + 16, 0xFF, 8); /* Frame index cannot fit the receive window. */
        break;
    case 3:
        data->bytes[0] = 0xFF; /* Unknown frame type. */
        break;
    case 4:
        data->bytes[3] = 1; /* Nonzero reserved bits. */
        break;
    default:
        twfRequire(false, "unknown malformed DATA fixture");
    }
    pump(257);
    twfRequire(f.upload_length == 0 && ! lineIsAlive(f.client_main) && ! lineIsAlive(f.server_main),
               "malformed DATA escaped its bounds or failed to abort the session");
    teardown();
}

static void caseInvalidWindow(unsigned mode)
{
    twfSetCase("ConnectionStripe rejects WINDOW byte/frame boundaries which do not match sent records");
    setup(8);
    start(SIZE_MAX);
    sendPattern(true, 16384, 23);
    for (unsigned i = 0; i < f.lane_count; ++i)
        while (deliver(i, true, SIZE_MAX))
            ;
    wire_piece_t *window = f.lanes[0].download.head;
    twfRequire(window != NULL && window->length == 24 && window->bytes[0] == 4 && window->bytes[23] == 1,
               "fixture did not capture credit for exactly one transmitted record");
    switch (mode)
    {
    case 0:
        memoryZero(window->bytes + 8, 8);
        window->bytes[15] = 1; /* Within the sent range, but not the record end. */
        break;
    case 1:
        window->bytes[23] = 0; /* Advances bytes without acknowledging a record. */
        break;
    case 2:
        window->bytes[23] = 2; /* Acknowledges a record that has never been sent. */
        break;
    case 3:
        memorySet(window->bytes + 8, 0xFF, 8); /* Advances beyond every sent byte. */
        break;
    default:
        twfRequire(false, "unknown malformed WINDOW fixture");
    }
    pump(7);
    twfRequire(! lineIsAlive(f.client_main) && ! lineIsAlive(f.server_main) && f.app_finishes == 1 &&
                   f.backend_finishes == 1,
               "inconsistent receive credit did not terminate the invalid session");
    teardown();
}

static void caseReentrant(unsigned mode)
{
    twfSetCase("ConnectionStripe synchronous application rejection settles every line");
    setup(8);
    f.reject_backend_init        = mode == 0;
    f.reject_application_est     = mode == 1;
    f.reject_backend_payload     = mode == 2;
    f.reject_application_payload = mode == 3;
    start(SIZE_MAX);
    if (mode == 2)
        sendPattern(true, 32749, 71);
    else if (mode == 3)
        sendPattern(false, 32749, 71);
    pump(SIZE_MAX);
    twfRequire(! lineIsAlive(f.client_main), "synchronous rejection left the client application alive");
    if (f.server_main != NULL)
        twfRequire(! lineIsAlive(f.server_main), "synchronous rejection left the owned backend line alive");
    teardown();
}

static void caseSettings(void)
{
    twfSetCase("ConnectionStripe rejects malformed connection counts and resource limits");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 64 * 1024, 64);
    const struct
    {
        const char *settings;
        bool        client, server;
        bool        add_connections;
    } cases[] = {
        {"{}", false, true, false},
        {"{\"connections\":1}", true, false, false},
        {"{\"connections\":8}", true, false, false},
        {"{\"connections\":32}", true, false, false},
        {"{\"connections\":0}", false, false, false},
        {"{\"connections\":33}", false, false, false},
        {"{\"connections\":-1}", false, false, false},
        {"{\"connections\":1.5}", false, false, false},
        {"{\"connections\":null}", false, false, false},
        {"{\"connections\":true}", false, false, false},
        {"{\"connections\":\"8\"}", false, false, false},
        {"{\"connections\":8,\"connections\":8}", false, false, false},
        {"{\"max-connections\":1}", false, true, true},
        {"{\"max-connections\":32}", false, true, true},
        {"{\"max-connections\":33}", false, false, true},
        {"{\"max-connections\":null}", false, false, true},
        {"{\"receive-window-bytes\":16384}", true, true, true},
        {"{\"receive-window-bytes\":16777216}", true, true, true},
        {"{\"receive-window-bytes\":16383}", false, false, true},
        {"{\"receive-window-bytes\":16777217}", false, false, true},
        {"{\"receive-window-bytes\":null}", false, false, true},
        {"{\"receive-window-bytes\":16384.5}", false, false, true},
        {"{\"max-buffered-bytes\":65536}", true, true, true},
        {"{\"max-buffered-bytes\":67108864}", true, true, true},
        {"{\"max-buffered-bytes\":65535}", false, false, true},
        {"{\"max-buffered-bytes\":67108865}", false, false, true},
        {"{\"max-buffered-bytes\":\"4194304\"}", false, false, true},
        {"{\"setup-timeout-ms\":1,\"drain-timeout-ms\":600000}", true, true, true},
        {"{\"setup-timeout-ms\":0}", false, false, true},
        {"{\"drain-timeout-ms\":600001}", false, false, true},
        {"{\"max-sessions\":1}", true, true, true},
        {"{\"max-sessions\":65536}", true, true, true},
        {"{\"max-sessions\":65537}", false, false, true},
        {"{\"max-pending-connections\":1}", false, true, true},
        {"{\"max-pending-connections\":65536}", false, true, true},
        {"{\"max-pending-connections\":65537}", false, false, true},
        {"{\"connection\":8}", false, false, true},
        {"[]", false, false, false},
        {"null", false, false, false},
    };
    for (unsigned role = 0; role < 2; ++role)
        for (unsigned i = 0; i < ARRAY_SIZE(cases); ++i)
        {
            twfSetCase(cases[i].settings);
            node_t node             = role == 0 ? nodeConnectionStripeClientGet() : nodeConnectionStripeServerGet();
            node.name               = (char *) "configuration-fixture";
            node.next               = (char *) "fixture-neighbor";
            node.node_settings_json = cJSON_Parse(cases[i].settings);
            twfRequire(node.node_settings_json != NULL, "fixture settings failed to parse");
            if (role == 0 && cases[i].add_connections)
                cJSON_AddNumberToObject(node.node_settings_json, "connections", 8);
            tunnel_t *instance = node.createHandle(&node);
            twfRequire((instance != NULL) == (role == 0 ? cases[i].client : cases[i].server),
                       "stripe constructor accepted an invalid setting or rejected a valid boundary");
            if (instance != NULL)
                instance->onDestroy(instance, wwLifecycleStartupRollback());
            cJSON_Delete(node.node_settings_json);
            memoryFree(node.type);
        }
    twfWorkerEnvTeardown(&env);
}

int main(void)
{
    twfRequire(globalstateInitializeSecureRandom(), "secure random initialization failed");
    twfRequire(frandGlobalInit(), "fast random global initialization failed");
    frandInit();
    caseSettings();
    caseDuplex(1, SIZE_MAX);
    caseDuplex(8, 317);
    caseDuplex(32, SIZE_MAX);
    caseServerFirst();
    caseServerFirstFinishDuringInit();
    caseServerFirstDataBeforeReady();
    caseResumePayload(true, false);
    caseResumePayload(false, false);
    caseResumePayload(true, true);
    caseResumePayload(false, true);
    caseReceiveWindow(true);
    caseReceiveWindow(false);
    caseDuplexReceiveWindow();
    caseFrameWindow(true);
    caseFrameWindow(false);
    caseCloseOvertakesData(true);
    caseCloseOvertakesData(false);
    caseCloseAfterQuiesce(true);
    caseCloseAfterQuiesce(false);
    caseJoinAfterQuiesce();
    caseTransportFailure(true);
    caseTransportFailure(false);
    caseSiblingFinishReentry(true);
    caseSiblingFinishReentry(false);
    for (unsigned mode = 0; mode < 6; ++mode)
        caseInvalidJoin(mode);
    for (unsigned mode = 0; mode < 5; ++mode)
        caseInvalidData(mode);
    for (unsigned mode = 0; mode < 4; ++mode)
        caseInvalidWindow(mode);
    for (unsigned mode = 0; mode < 4; ++mode)
        caseReentrant(mode);
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    puts("connectionstripe_session_test: all cases passed");
    return 0;
}
