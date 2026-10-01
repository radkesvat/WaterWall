#include "ReverseServer/interface.h"
#include "ReverseServer/structure.h"
#include "tunnel_line_failure_harness.h"

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
    bool             close_on_payload;
} reverse_fixture_t;

static reverse_fixture_t *fixture;
static uint8_t            handshake[] = {1, 2, 3};

sbuf_t *__real_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict b1, sbuf_t *restrict b2);
sbuf_t *__wrap_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict b1, sbuf_t *restrict b2);

sbuf_t *__wrap_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict b1, sbuf_t *restrict b2)
{
    sbuf_t *merged = __real_sbufAppendMerge(pool, b1, b2);
    // The helper recycles internally, beyond the bufferpoolReuseBuffer linker wrapper.
    twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, b2);
    twfLedgerRemember(g_twf_buffers.recycled, &g_twf_buffers.recycled_count, b2, "too many merged buffers");
    if (merged != b1)
    {
        twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, b1);
        twfLedgerRemember(g_twf_buffers.live, &g_twf_buffers.live_count, merged, "too many grown buffers");
    }
    return merged;
}

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
    twfLinePoolSetup(&f->lines, f->reverse->lstate_size, 4);
    f->u = twfLinePoolCreateLine(&f->lines);
    f->d = twfLinePoolCreateLine(&f->lines);
    lineRef(f->u);
    lineRef(f->d);
    reverseserverTunnelUpStreamInit(f->reverse, f->d);
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
    twfRequire(ls->buffering && ! sbufIsSplice(ls->buffering), "waiting buffer must be ordinary");
    twfRequire(sbufGetLength(ls->buffering) == length && memcmp(sbufGetRawPtr(ls->buffering), bytes, length) == 0,
               "waiting bytes changed");
}

static void testPairing(bool local_first, bool splice, bool close_on_replay)
{
    twfSetCase("split handshake, waiting merge, pair replay and opaque relay");
    reverse_fixture_t f;
    setup(&f);
    if (local_first)
    {
        reverseserverTunnelDownStreamPayload(f.reverse, f.u, payload("lo", 2, splice, 0));
        requireOrdinaryPending(f.u, "lo", 2);
        reverseserverTunnelDownStreamPayload(f.reverse, f.u, payload("cal", 3, ! splice && WW_HAVE_SPLICE, 0));
        requireOrdinaryPending(f.u, "local", 5);
    }
    reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload(handshake, 1, splice, 0));
    requireOrdinaryPending(f.d, handshake, 1);
    const uint8_t rest[] = {2, 3, 'r', 'e'};
    f.close_on_payload   = close_on_replay && local_first;
    reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload(rest, sizeof(rest), splice, splice ? 1 : 0));
    if (! local_first)
    {
        requireOrdinaryPending(f.d, "re", 2);
        reverseserverTunnelUpStreamPayload(f.reverse, f.d, payload("mote", 4, splice, 0));
        requireOrdinaryPending(f.d, "remote", 6);
        f.close_on_payload = close_on_replay;
        reverseserverTunnelDownStreamPayload(f.reverse, f.u, payload("local", 5, splice, 0));
    }
    twfRequire(f.downstream_length == 5 && memcmp(f.downstream, "local", 5) == 0, "local replay changed bytes");
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
        twfRequireEqualText(f.next_trace.seq, "EUR", "paired upstream pressure mapping changed");
        twfRequireEqualText(f.prev_trace.seq, "eur", "paired downstream pressure mapping changed");
    }
    teardown(&f);
}

static void testUnpairedClose(bool splice, unsigned mode)
{
    twfSetCase("invalid or incomplete handshake and waiting overflow cleanup");
    reverse_fixture_t f;
    setup(&f);
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
        uint32_t limit = (uint32_t) reverseserverWaitingLimit(line);
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

int main(void)
{
    for (unsigned splice = 0; splice <= WW_HAVE_SPLICE; ++splice)
    {
        for (unsigned local_first = 0; local_first < 2; ++local_first)
        {
            testPairing(local_first != 0, splice != 0, false);
            testPairing(local_first != 0, splice != 0, true);
        }
        for (unsigned mode = 0; mode < 4; ++mode)
            testUnpairedClose(splice != 0, mode);
    }
    node_t node = nodeReverseServerGet();
    twfRequire(node.flags == kNodeFlagSupportsSplice, "ReverseServer lost splice capability");
    memoryFree(node.type);
    puts("ReverseServer ordinary/splice tests passed");
    return 0;
}
