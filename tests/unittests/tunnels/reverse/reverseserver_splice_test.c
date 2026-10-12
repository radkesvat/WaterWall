/*
 * Covers: reverseserver splice; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: pairing, activation through Pause, reentrant startup, waiting cleanup and settings
 * Checks: Assertion labels include: paired relay replaced the original buffer; unpaired replay must use
 * ordinary storage; relay lost onward padding; test capture overflow
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.reverseserver_splice_unit
 */
#include "ReverseServer/interface.h"
#include "ReverseServer/structure.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"

#if WW_HAVE_SPLICE
#include <unistd.h>
#endif

typedef struct reverse_fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  lines;
    twf_trace_t      prev_trace;
    twf_trace_t      next_trace;
    tunnel_t        *prev;
    tunnel_t        *next;
    tunnel_t        *reverse;
    line_t          *u;
    line_t          *d;
    uint8_t          upstream[8192];
    uint8_t          downstream[8192];
    uint32_t         upstream_length;
    uint32_t         downstream_length;
    sbuf_t          *expected_identity;
    void (*on_activation)(struct reverse_fixture_s *f);
    bool             close_on_payload;
    bool             user_initialized;
    unsigned         activation_count;
} reverse_fixture_t;

static reverse_fixture_t *fixture;
static uint8_t            handshake[] = {1, 2, 3};


static void ownerFinish(tunnel_t *t, line_t *line)
{
    twf_trace_t *trace = twfTrace(t);
    if (t == fixture->prev)
        ++trace->prev_finish;
    else
        ++trace->next_finish;
    lineDestroy(line);
}

static void receive(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    reverse_fixture_t *f = fixture;
    const bool         activation = t == f->prev && f->activation_count == 0;
    if (activation)
    {
        reverseserver_tstate_t *ts = tunnelGetState(f->reverse);
        uint8_t                 header[kReverseActivationHeaderSize];
        twfRequire(! sbufIsSplice(buf) && sbufGetLength(buf) >= sizeof(header), "activation header missing");
        sbufReadRangeToMemory(buf, header, sizeof(header));
        const uint32_t size = reverseActivationReadSize(header);
        twfRequire(size >= ts->activation_min_size && size <= ts->activation_max_size,
                   "activation size outside the configured range");
        twfRequire(sbufGetLength(buf) == size - sizeof(header), "activation handoff included application bytes");
        sbufShiftRight(buf, size - sizeof(header));
        ++f->activation_count;
    }
    if (f->expected_identity)
        twfRequire(buf == f->expected_identity, "paired relay replaced the original buffer");
    else
        twfRequire(! sbufIsSplice(buf), "unpaired replay must use ordinary storage");
    twfRequire(sbufGetLeftCapacity(buf) >= 64, "relay lost onward padding");
    uint8_t  *bytes  = t == f->prev ? f->downstream : f->upstream;
    uint32_t *length = t == f->prev ? &f->downstream_length : &f->upstream_length;
    twfRequire(*length + sbufGetLength(buf) <= sizeof(f->upstream), "test capture overflow");
    uint32_t received = sbufGetLength(buf);
    sbufReadRangeToMemory(buf, bytes + *length, received);
    *length += received;
    lineReuseBuffer(line, buf);
    if (activation && f->on_activation)
        f->on_activation(f);
    if (f->close_on_payload)
    {
        twfRequire(t == f->prev, "close must originate from reverse transport");
        reverseserverTunnelUpStreamFinish(f->reverse, line);
        lineDestroy(line);
    }
}

static void setup(reverse_fixture_t *f)
{
    memoryZero(f, sizeof(*f));
    fixture = f;
    twfWorkerEnvSetupWithBufferSizes(&f->env, 1024, 256, 96, 4096, 32768);
    f->prev             = twfCreatePrevTunnel(&f->prev_trace);
    f->next             = twfCreateNextTunnel(&f->next_trace);
    f->prev->fnPayloadD = f->next->fnPayloadU = receive;
    f->prev->fnFinD = f->next->fnFinU = ownerFinish;
    f->reverse                        = tunnelCreate(
        NULL, sizeof(reverseserver_tstate_t) + sizeof(reverseserver_thread_box_t), sizeof(reverseserver_lstate_t));
    twfRequire(f->reverse != NULL, "construct reverse fixture");
    tunnelBind(f->prev, f->reverse);
    tunnelBind(f->reverse, f->next);
    reverseserver_tstate_t *ts = tunnelGetState(f->reverse);
    ts->handshake_bytes        = handshake;
    ts->handshake_length       = sizeof(handshake);
    ts->activation_min_size = ts->activation_max_size = 64;
    twfLinePoolSetup(&f->lines, f->reverse->lstate_size, 4);
    f->u = twfLinePoolCreateLine(&f->lines);
    f->d = twfLinePoolCreateLine(&f->lines);
    lineRef(f->u);
    lineRef(f->d);
    reverseserverTunnelUpStreamInit(f->reverse, f->d);
}

static void initUser(reverse_fixture_t *f)
{
    f->user_initialized = true;
    reverseserverTunnelDownStreamInit(f->reverse, f->u);
}

static void teardown(reverse_fixture_t *f)
{
    if (lineIsAlive(f->d))
    {
        reverseserverTunnelUpStreamFinish(f->reverse, f->d);
        lineDestroy(f->d);
    }
    if (lineIsAlive(f->u))
    {
        if (f->user_initialized)
            reverseserverTunnelDownStreamFinish(f->reverse, f->u);
        lineDestroy(f->u);
    }
    twfRequireLineStateZeroed(f->d, f->reverse, "reverse half retained line state");
    twfRequireLineStateZeroed(f->u, f->reverse, "local half retained line state");
    twfRequire(twfLineRefCount(f->d) == 1 && twfLineRefCount(f->u) == 1, "close leaked line references");
    lineUnref(f->u);
    lineUnref(f->d);
    twfRequire(masterpoolGetCheckedOut(f->lines.master) == 0, "close retained a pooled line");
    twfLinePoolTeardown(&f->lines);
    tunnelDestroy(f->reverse);
    tunnelDestroy(f->prev);
    tunnelDestroy(f->next);
    twfWorkerEnvTeardown(&f->env);
    fixture = NULL;
}

static sbuf_t *payload(const void *data, uint32_t length, bool splice, uint32_t prefix)
{
    buffer_pool_t *pool = fixture->env.pool;
    if (! splice)
    {
        sbuf_t *buf = bufferpoolGetBestFit(pool, length, 96);
        sbufWrite(buf, data, length);
        sbufSetLength(buf, length);
        return buf;
    }
#if WW_HAVE_SPLICE
    sbuf_t *buf = bufferpoolGetSpliceBuffer(pool);
    twfRequire(buf != NULL && prefix <= length && prefix <= 32, "allocate splice fixture");
    twfRequire(write(sbufSpliceMetadata(buf).pipefd[1], (const uint8_t *) data + prefix, length - prefix) ==
                   (ssize_t) (length - prefix),
               "populate private pipe");
    buf->capacity = buf->l_pad + length - prefix;
    sbufSetLength(buf, length - prefix);
    sbufShiftLeft(buf, prefix);
    sbufWrite(buf, data, prefix);
    return buf;
#else
    discard data;
    discard length;
    discard prefix;
    twfRequire(false, "splice fixture on unsupported build");
    return NULL;
#endif
}

static void requireOrdinaryPending(line_t *line, const void *bytes, uint32_t length)
{
    reverseserver_lstate_t *ls = lineGetState(line, fixture->reverse);
    twfRequire(bufferqueueGetBufLen(&ls->pending) == length, "waiting length changed");
    uint32_t offset = 0;
    c_foreach(entry, ww_sbuffer_queue_t, ls->pending.q)
    {
        const sbuf_t *buf = *entry.ref;
        twfRequire(! sbufIsSplice(buf), "waiting buffer must be ordinary");
        twfRequire(memcmp(sbufGetRawPtr(buf), (const uint8_t *) bytes + offset, sbufGetLength(buf)) == 0,
                   "waiting bytes changed");
        offset += sbufGetLength(buf);
    }
}

static void testPairing(bool local_first, bool splice, bool close_on_replay)
{
    twfSetCase("split handshake, waiting merge, pair replay and opaque relay");
    reverse_fixture_t f;
    setup(&f);
    if (local_first)
    {
        initUser(&f);
        reverseserverTunnelDownStreamPayload(f.reverse, f.u, payload("lo", 2, splice, 0));
        requireOrdinaryPending(f.u, "lo", 2);
        reverseserverTunnelDownStreamPayload(f.reverse, f.u, payload("cal", 3, ! splice && WW_HAVE_SPLICE, 0));
        requireOrdinaryPending(f.u, "local", 5);
    }
    reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload(handshake, 1, splice, 0));
    twfRequire(((reverseserver_lstate_t *) lineGetState(f.d, f.reverse))->handshake_read == 1,
               "split handshake did not retain its bounded parser position");
    const uint8_t rest[] = {2, 3, 'r', 'e'};
    f.close_on_payload   = close_on_replay && local_first;
    reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload(rest, sizeof(rest), splice, splice ? 1 : 0));
    if (! local_first)
    {
        requireOrdinaryPending(f.d, "re", 2);
        reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload("mote", 4, splice, 0));
        requireOrdinaryPending(f.d, "remote", 6);
        f.close_on_payload = close_on_replay;
        initUser(&f);
        if (! close_on_replay)
        {
            f.expected_identity = payload("local", 5, splice, 0);
            reverseserverTunnelDownStreamPayload(f.reverse, f.u, f.expected_identity);
            f.expected_identity = NULL;
        }
    }
    const uint32_t local_length = close_on_replay ? 0 : 5;
    twfRequire(f.activation_count == 1, "pair did not emit exactly one activation");
    twfRequire(f.downstream_length == local_length && memcmp(f.downstream, "local", local_length) == 0,
               "local replay changed bytes");
    if (close_on_replay)
    {
        twfRequire(! lineIsAlive(f.u) && ! lineIsAlive(f.d), "reentrant close left a live half");
        twfRequire(f.upstream_length == 0, "replay continued after close");
    }
    else
    {
        const char *expected = local_first ? "re" : "remote";
        twfRequire(f.upstream_length == strlen(expected) && memcmp(f.upstream, expected, strlen(expected)) == 0,
                   "reverse handshake stripping/replay changed bytes");
        uint8_t opaque[3000];
        for (uint32_t i = 0; i < sizeof(opaque); ++i)
            opaque[i] = (uint8_t) i;
        f.expected_identity = payload(opaque, sizeof(opaque), splice, splice ? 4 : 0);
        reverseserverTunnelUpStreamPayload(f.reverse, f.d, f.expected_identity);
        twfRequire(memcmp(f.upstream + strlen(expected), opaque, sizeof(opaque)) == 0, "opaque upstream differs");
        f.expected_identity = payload(opaque, sizeof(opaque), splice, splice ? 4 : 0);
        reverseserverTunnelDownStreamPayload(f.reverse, f.u, f.expected_identity);
        twfRequire(memcmp(f.downstream + 5, opaque, sizeof(opaque)) == 0, "opaque downstream differs");
        reverseserverTunnelUpStreamPause(f.reverse, f.d);
        reverseserverTunnelUpStreamResume(f.reverse, f.d);
        reverseserverTunnelDownStreamPause(f.reverse, f.u);
        reverseserverTunnelDownStreamResume(f.reverse, f.u);
        twfRequireEqualText(f.next_trace.seq, "EURUR", "paired upstream pressure mapping changed");
        twfRequireEqualText(f.prev_trace.seq, "eurur", "paired downstream pressure mapping changed");
    }
    teardown(&f);
}

static void testUnpairedClose(bool splice, unsigned mode)
{
    twfSetCase("invalid or incomplete handshake and waiting overflow cleanup");
    reverse_fixture_t f;
    setup(&f);
    if (mode == 2)
        initUser(&f);
    if (mode < 2)
    {
        const uint8_t invalid[] = {1, 2, 9};
        reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload(invalid, mode ? 1 : 3, splice, 0));
        twfRequire(lineIsAlive(f.d) == (mode == 1), "invalid/incomplete handshake closure changed");
    }
    else
    {
        const bool local = mode == 2;
        line_t    *line  = local ? f.u : f.d;
        if (! local)
            reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload(handshake, sizeof(handshake), splice, 0));
        uint8_t bytes[4096];
        memorySet(bytes, 'x', sizeof(bytes));
        uint32_t limit = kReverseServerPendingBytes;
        for (uint32_t total = 0; total < limit;)
        {
            uint32_t count = min((uint32_t) sizeof(bytes), limit - total);
            sbuf_t  *buf   = payload(bytes, count, splice, 0);
            if (local)
                reverseserverTunnelDownStreamPayload(f.reverse, line, buf);
            else
                reverseserverTunnelUpStreamPayload(f.reverse, line, buf);
            total += count;
        }
        twfRequire(lineIsAlive(line), "waiting closed at the exact byte limit");
        sbuf_t *buf = payload(bytes, 1, splice, 0);
        if (local)
            reverseserverTunnelDownStreamPayload(f.reverse, line, buf);
        else
            reverseserverTunnelUpStreamPayload(f.reverse, line, buf);
        twfRequire(! lineIsAlive(line), "waiting overflow did not close its owner");
    }
    teardown(&f);
}

static void testSilentPairing(bool user_first, bool splice, bool paused)
{
    twfSetCase("silent user pairs on Init and receives a server greeting");
    reverse_fixture_t f;
    setup(&f);
    if (user_first)
        initUser(&f);
    if (paused)
        reverseserverTunnelUpStreamPause(f.reverse, f.d);
    reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload(handshake, sizeof(handshake), splice, 0));
    if (! user_first)
        initUser(&f);
    twfRequire(f.activation_count == 1 && f.downstream_length == 0, "silent user did not activate exactly once");
    reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload("SSH-2.0-test\r\n", 14, false, 0));
    twfRequire(f.upstream_length == 14 && memcmp(f.upstream, "SSH-2.0-test\r\n", 14) == 0,
               "silent user missed the server greeting");
    if (paused)
    {
        reverseserverTunnelUpStreamResume(f.reverse, f.d);
        twfRequire(f.activation_count == 1, "silent user's activation repeated on Resume");
    }
    teardown(&f);
}

static void testPausedActivation(bool close_waiting, bool splice, uint32_t activation_size)
{
    twfSetCase("activation passes Pause once while application backlog waits for Resume");
    reverse_fixture_t f;
    setup(&f);
    reverseserver_tstate_t *ts = tunnelGetState(f.reverse);
    ts->activation_min_size = ts->activation_max_size = activation_size;
    initUser(&f);
    reverseserverTunnelDownStreamPayload(f.reverse, f.u, payload("queued", 6, splice, 0));
    reverseserverTunnelUpStreamPause(f.reverse, f.d);
    reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload(handshake, sizeof(handshake), splice, 0));
    twfRequire(f.activation_count == 1 && f.downstream_length == 0,
               "Pause blocked activation or released user backlog");
    requireOrdinaryPending(f.u, "queued", 6);
    reverseserverTunnelDownStreamPayload(f.reverse, f.u, payload("tail", 4, splice, 0));
    twfRequire(f.activation_count == 1 && f.downstream_length == 0, "new input bypassed older paused user backlog");
    if (! close_waiting)
    {
        reverseserverTunnelUpStreamResume(f.reverse, f.d);
        twfRequire(f.activation_count == 1 && f.downstream_length == 10 && memcmp(f.downstream, "queuedtail", 10) == 0,
                   "Resume did not preserve application FIFO or repeated activation");
        reverseserverTunnelUpStreamPause(f.reverse, f.d);
        f.expected_identity = payload("direct", 6, splice, 0);
        reverseserverTunnelDownStreamPayload(f.reverse, f.u, f.expected_identity);
        twfRequire(f.downstream_length == 16 && memcmp(f.downstream + 10, "direct", 6) == 0,
                   "paired forwarding retained an admitted payload solely for Pause");
    }
    teardown(&f);
}

static void queueDuringActivation(reverse_fixture_t *f)
{
    reverseserverTunnelDownStreamPayload(f->reverse, f->u, payload("tail", 4, WW_HAVE_SPLICE, 0));
    reverseserverTunnelUpStreamPayload(f->reverse, f->d, payload("new", 3, WW_HAVE_SPLICE, 0));
    twfRequire(f->downstream_length == 0 && f->upstream_length == 0,
               "reentrant input or Resume bypassed the activation handoff barrier");
}

static void resumeDuringActivation(reverse_fixture_t *f)
{
    reverseserverTunnelUpStreamResume(f->reverse, f->d);
    queueDuringActivation(f);
}

static void pauseDuringActivation(reverse_fixture_t *f)
{
    reverseserverTunnelUpStreamPause(f->reverse, f->d);
    queueDuringActivation(f);
}

static void testActivationReentry(bool splice, bool resume)
{
    twfSetCase("reentrant activation preserves FIFO and the latest Pause permission");
    reverse_fixture_t f;
    setup(&f);
    initUser(&f);
    reverseserverTunnelDownStreamPayload(f.reverse, f.u, payload("head", 4, splice, 0));
    if (resume)
        reverseserverTunnelUpStreamPause(f.reverse, f.d);
    f.on_activation         = resume ? resumeDuringActivation : pauseDuringActivation;
    const uint8_t initial[] = {1, 2, 3, 'o', 'l', 'd'};
    reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload(initial, sizeof(initial), splice, 0));
    twfRequire(f.activation_count == 1 && f.upstream_length == 6 && memcmp(f.upstream, "oldnew", 6) == 0,
               "activation reordered reverse-side startup data");
    if (! resume)
    {
        twfRequire(f.downstream_length == 0, "Pause during activation released application backlog");
        requireOrdinaryPending(f.u, "headtail", 8);
        reverseserverTunnelUpStreamResume(f.reverse, f.d);
    }
    twfRequire(f.activation_count == 1 && f.downstream_length == 8 && memcmp(f.downstream, "headtail", 8) == 0,
               "activation reordered user startup data or was repeated on Resume");
    teardown(&f);
}

static void resumeBeforeActivation(tunnel_t *t, line_t *d)
{
    reverse_fixture_t *f = fixture;
    twfRequire(t == f->prev && d == f->d, "startup Pause reached the wrong half");
    reverseserverTunnelUpStreamResume(f->reverse, f->d);
    reverseserverTunnelDownStreamPayload(f->reverse, f->u, payload("tail", 4, false, 0));
}

static void closeBeforeActivation(tunnel_t *t, line_t *d)
{
    reverse_fixture_t *f = fixture;
    twfRequire(t == f->prev && d == f->d, "startup Pause reached the wrong half");
    reverseserverTunnelUpStreamFinish(f->reverse, d);
    lineDestroy(d);
}

static void testActivationPauseReentry(bool close)
{
    twfSetCase("waiting Pause can pair reentrantly or Finish before activation");
    reverse_fixture_t f;
    setup(&f);
    initUser(&f);
    reverseserverTunnelDownStreamPayload(f.reverse, f.u, payload("head", 4, false, 0));
    reverseserverTunnelUpStreamPause(f.reverse, f.d);
    f.prev->fnPauseD = close ? closeBeforeActivation : resumeBeforeActivation;
    reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload(handshake, sizeof(handshake), false, 0));
    if (close)
    {
        twfRequire(lineIsAlive(f.u) && ! lineIsAlive(f.d) && f.activation_count == 0 && f.downstream_length == 0,
                   "unpaired Finish changed the other waiting half or sent output");
    }
    else
    {
        twfRequire(f.activation_count == 1 && f.downstream_length == 8 && memcmp(f.downstream, "headtail", 8) == 0,
                   "source reentry reordered activation and application data");
    }
    teardown(&f);
}

static void testActivationSettings(void)
{
    twfSetCase("strict activation range JSON validation");
    twf_worker_env_t env;
    twfWorkerEnvSetupWithBufferSizes(&env, 1024, 256, 96, 4096, 32768);
    const char *settings[] = {"{}",
                              "{\"activation-min-size\":4,\"activation-max-size\":4}",
                              "{\"activation-min-size\":65536,\"activation-max-size\":65536}",
                              "{\"activation-min-size\":3}",
                              "{\"activation-max-size\":65537}",
                              "{\"activation-min-size\":64.5}",
                              "{\"activation-max-size\":\"1024\"}",
                              "{\"activation-min-size\":1025}",
                              "{\"activation-max-size\":63}",
                              "{\"activation-min-size\":null}"};
    for (unsigned i = 0; i < sizeof(settings) / sizeof(settings[0]); ++i)
    {
        node_t node             = nodeReverseServerGet();
        node.node_settings_json = cJSON_Parse(settings[i]);
        tunnel_t *t             = reverseserverTunnelCreate(&node);
        twfRequire((t != NULL) == (i < 3), "activation range validation accepted/rejected the wrong configuration");
        if (t)
            t->onDestroy(t, wwLifecycleProcessShutdown());
        cJSON_Delete(node.node_settings_json);
        memoryFree(node.type);
    }
    twfWorkerEnvTeardown(&env);
}

static void testWaitingPause(void)
{
    twfSetCase("waiting sources pause after Est or a complete handshake");
    reverse_fixture_t f;
    setup(&f);
    initUser(&f);
    twfRequireEqualText(f.next_trace.seq, "EU", "unpaired user was not paused after Est");
    teardown(&f);

    setup(&f);
    reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload(handshake, 1, false, 0));
    twfRequireEqualText(f.prev_trace.seq, "e", "reverse source paused before the complete handshake");
    reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload(handshake + 1, 2, false, 0));
    twfRequireEqualText(f.prev_trace.seq, "eu", "authenticated waiting reverse source was not paused");
    initUser(&f);
    twfRequireEqualText(f.next_trace.seq, "EUR", "pairing did not release the user waiting hold once");
    twfRequireEqualText(f.prev_trace.seq, "eur", "pairing did not release the reverse waiting hold once");
    twfRequire(f.activation_count == 1, "waiting Pause blocked activation");
    teardown(&f);
}

static void pauseUserConsumerOnEst(tunnel_t *t, line_t *u)
{
    discard t;
    reverseserverTunnelDownStreamPause(fixture->reverse, u);
}

static void testPendingBudget(bool user, bool entries, bool paired)
{
    twfSetCase("exact and overflow application byte/buffer budgets while waiting or paired");
    reverse_fixture_t f;
    setup(&f);
    if (user)
        initUser(&f);
    else
        reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload(handshake, sizeof(handshake), false, 0));
    line_t        *line  = user ? f.u : f.d;
    const uint32_t count = entries ? kReverseServerPendingBuffers : 1;
    const uint32_t size  = entries ? 1 : kReverseServerPendingBytes;
    for (uint32_t i = 0; i < count; ++i)
    {
        sbuf_t *buf = bufferpoolGetBestFit(f.env.pool, size, 96);
        memorySet(sbufGetMutablePtr(buf), 'x', size);
        sbufSetLength(buf, size);
        if (user)
            reverseserverTunnelDownStreamPayload(f.reverse, line, buf);
        else
            reverseserverTunnelUpStreamPayload(f.reverse, line, buf);
    }
    reverseserver_lstate_t *ls = lineGetState(line, f.reverse);
    twfRequire(lineIsAlive(line) && bufferqueueGetBufCount(&ls->pending) == count &&
                   bufferqueueGetBufLen(&ls->pending) == (size_t) count * size,
               "retention refused its exact inclusive budget");
    if (paired)
    {
        if (user)
        {
            reverseserverTunnelUpStreamPause(f.reverse, f.d);
            reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload(handshake, sizeof(handshake), false, 0));
        }
        else
        {
            f.next->fnEstU = pauseUserConsumerOnEst;
            initUser(&f);
        }
        twfRequire(f.activation_count == 1 && f.downstream_length == 0 && f.upstream_length == 0,
                   "paused startup backlog leaked into activation or replay");
    }
    for (unsigned i = 0; i < 3; ++i)
    {
        if (user)
            reverseserverTunnelDownStreamPayload(f.reverse, line, payload("", 0, false, 0));
        else
            reverseserverTunnelUpStreamPayload(f.reverse, line, payload("", 0, false, 0));
    }
    twfRequire(lineIsAlive(line) && bufferqueueGetBufCount(&ls->pending) == count,
               "empty application input consumed backlog entries");
    if (user)
        reverseserverTunnelDownStreamPayload(f.reverse, line, payload("x", 1, false, 0));
    else
        reverseserverTunnelUpStreamPayload(f.reverse, line, payload("x", 1, false, 0));
    twfRequire(! lineIsAlive(line), "retention accepted bytes or buffers above its hard limit");
    if (paired)
        twfRequire(! lineIsAlive(f.u) && ! lineIsAlive(f.d), "paired budget refusal left a live half");
    teardown(&f);
}

static void testCombinedConsumerHolds(void)
{
    twfSetCase("pairing and one consumer Resume cannot clear another consumer's Pause");
    reverse_fixture_t f;
    setup(&f);
    initUser(&f);
    reverseserverTunnelDownStreamPayload(f.reverse, f.u, payload("user", 4, false, 0));
    reverseserverTunnelUpStreamPause(f.reverse, f.d);
    reverseserverTunnelDownStreamPause(f.reverse, f.u);
    const uint8_t initial[] = {1, 2, 3, 'p', 'e', 'e', 'r'};
    reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload(initial, sizeof(initial), false, 0));
    twfRequire(f.activation_count == 1 && f.upstream_length == 0 && f.downstream_length == 0,
               "pairing released a paused application backlog");
    twfRequireEqualText(f.next_trace.seq, "EU", "pairing sent a premature user Resume");
    twfRequireEqualText(f.prev_trace.seq, "eu", "pairing sent a premature reverse Resume");
    reverseserverTunnelUpStreamResume(f.reverse, f.d);
    twfRequire(f.downstream_length == 4 && f.upstream_length == 0,
               "one Resume released the wrong application direction");
    twfRequireEqualText(f.prev_trace.seq, "eu", "reverse source resumed while the user consumer remained paused");
    reverseserverTunnelDownStreamResume(f.reverse, f.u);
    twfRequire(f.upstream_length == 4 && memcmp(f.upstream, "peer", 4) == 0, "user Resume lost reverse backlog");
    twfRequireEqualText(f.next_trace.seq, "EUR", "user source was not resumed once");
    twfRequireEqualText(f.prev_trace.seq, "eur", "reverse source was not resumed once");
    teardown(&f);
}

static void resumeAfterBacklog(tunnel_t *t, line_t *u)
{
    reverse_fixture_t *f = fixture;
    twfRequire(t == f->next && u == f->u && f->downstream_length == 4 && memcmp(f->downstream, "head", 4) == 0,
               "source Resume overtook older application backlog");
    reverseserverTunnelDownStreamPayload(f->reverse, u, payload("after", 5, false, 0));
}

static void closeOnUserPause(tunnel_t *t, line_t *u)
{
    twfRequire(t == fixture->next && u == fixture->u, "user Pause used the wrong exact line");
    reverseserverTunnelDownStreamFinish(fixture->reverse, u);
    lineDestroy(u);
}

static void closeOnUserResume(tunnel_t *t, line_t *u)
{
    twfRequire(fixture->downstream_length == 4, "Resume close overtook older application data");
    closeOnUserPause(t, u);
}

static void testSourceResumeClose(void)
{
    twfSetCase("Finish during startup Resume stops the remaining source notification");
    reverse_fixture_t f;
    setup(&f);
    initUser(&f);
    reverseserverTunnelDownStreamPayload(f.reverse, f.u, payload("head", 4, false, 0));
    reverseserverTunnelUpStreamPause(f.reverse, f.d);
    reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload(handshake, sizeof(handshake), false, 0));
    f.next->fnResumeU = closeOnUserResume;
    reverseserverTunnelUpStreamResume(f.reverse, f.d);
    twfRequire(! lineIsAlive(f.u) && ! lineIsAlive(f.d) && f.activation_count == 1 && f.prev_trace.prev_finish == 1 &&
                   f.next_trace.next_finish == 0,
               "Resume close left a live half or reflected Finish toward its sender");
    teardown(&f);
}

static void testSourceCallbackReentry(bool close)
{
    twfSetCase("waiting Pause may Finish; startup Resume follows older data before new input");
    reverse_fixture_t f;
    setup(&f);
    if (close)
    {
        f.next->fnPauseU = closeOnUserPause;
        initUser(&f);
        twfRequire(! lineIsAlive(f.u) && lineIsAlive(f.d) && f.activation_count == 0,
                   "waiting Pause close paired or retained the user line");
    }
    else
    {
        initUser(&f);
        reverseserverTunnelDownStreamPayload(f.reverse, f.u, payload("head", 4, false, 0));
        reverseserverTunnelUpStreamPause(f.reverse, f.d);
        reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload(handshake, sizeof(handshake), false, 0));
        f.next->fnResumeU = resumeAfterBacklog;
        reverseserverTunnelUpStreamResume(f.reverse, f.d);
        twfRequire(f.activation_count == 1 && f.downstream_length == 9 && memcmp(f.downstream, "headafter", 9) == 0,
                   "reentrant source Resume reordered data or activation");
    }
    teardown(&f);
}

int main(void)
{
    twfRequire(globalstateInitializeSecureRandom() && frandGlobalInit(), "random initialization failed");
    testWaitingPause();
    testCombinedConsumerHolds();
    testSourceCallbackReentry(false);
    testSourceCallbackReentry(true);
    testSourceResumeClose();
    for (unsigned user = 0; user < 2; ++user)
        for (unsigned entries = 0; entries < 2; ++entries)
            for (unsigned paired = 0; paired < 2; ++paired)
                testPendingBudget(user != 0, entries != 0, paired != 0);
    for (unsigned splice = 0; splice <= WW_HAVE_SPLICE; ++splice)
    {
        for (unsigned local_first = 0; local_first < 2; ++local_first)
        {
            testPairing(local_first != 0, splice != 0, false);
            testPairing(local_first != 0, splice != 0, true);
            testSilentPairing(local_first != 0, splice != 0, false);
            testSilentPairing(local_first != 0, splice != 0, true);
        }
        for (unsigned mode = 0; mode < 4; ++mode)
            testUnpairedClose(splice != 0, mode);
        const uint32_t sizes[] = {kReverseActivationHeaderSize, 64, kReverseActivationMaxSize};
        for (unsigned i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i)
        {
            testPausedActivation(false, splice != 0, sizes[i]);
            testPausedActivation(true, splice != 0, sizes[i]);
        }
        testActivationReentry(splice != 0, false);
        testActivationReentry(splice != 0, true);
    }
    testActivationPauseReentry(false);
    testActivationPauseReentry(true);
    testActivationSettings();
    node_t node = nodeReverseServerGet();
    twfRequire(node.flags == kNodeFlagSupportsSplice, "ReverseServer lost splice capability");
    memoryFree(node.type);
    frandThreadCleanup();
    frandGlobalCleanup();
    puts("ReverseServer ordinary/splice tests passed");
    return 0;
}
