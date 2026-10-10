/* Real private-pipe startup/relay, coalesced-body boundaries, queue admission,
 * retirement and reentrant close. Oracle reads are excluded from relay reads.
 * CTest: waterwall.connectionfisher{client,server}_{splice,no_splice}_unit
 */
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "fixtures/protocols/splice_source.h"

#ifdef TEST_FISHER_SERVER
#include "ConnectionFisherServer/interface.h"
#include "ConnectionFisherServer/structure.h"
#define nodeGet     nodeConnectionFisherServerGet
#define nodeCreate  connectionfisherserverTunnelCreate
#define MAX_PENDING kConnectionFisherServerMaxPendingBytes
#define MAX_BUFFERS kConnectionFisherServerMaxPendingBuffers
#define MARKER      "FISH?"
#else
#include "ConnectionFisherClient/interface.h"
#include "ConnectionFisherClient/structure.h"
#define nodeGet     nodeConnectionFisherClientGet
#define nodeCreate  connectionfisherclientTunnelCreate
#define MAX_PENDING kConnectionFisherMaxPendingUpBytes
#define MAX_BUFFERS kConnectionFisherMaxPendingBuffers
#define MARKER      "FISH!"
#endif

#include <unistd.h>

static twf_worker_env_t env;
static twf_line_pool_t  lines;
static node_t           metadata;
static tunnel_t        *node, *prev, *next;
static line_t          *main_line;
#ifndef TEST_FISHER_SERVER
static line_t *children[3];
#endif
static uint8_t  output[2][3 * 1024 * 1024];
static size_t   lengths[2], reads;
static unsigned calls[2], pipe_calls[2], finishes[2], inits;
static bool     measuring, nested, close_output, overflow_init, fail_queue;
static sbuf_t  *expected_identity;

ssize_t __real_read(int fd, void *destination, size_t bytes);
ssize_t __wrap_read(int fd, void *destination, size_t bytes);
ssize_t __wrap_read(int fd, void *destination, size_t bytes)
{
    const ssize_t result = __real_read(fd, destination, bytes);
    if (measuring && result > 0)
        reads += (size_t) result;
    return result;
}

bool __real_bufferqueueTryPushBack(buffer_queue_t *queue, sbuf_t **buf);
bool __wrap_bufferqueueTryPushBack(buffer_queue_t *queue, sbuf_t **buf);
bool __wrap_bufferqueueTryPushBack(buffer_queue_t *queue, sbuf_t **buf)
{
    return ! fail_queue && __real_bufferqueueTryPushBack(queue, buf);
}

sbuf_t *__real_sbufDuplicate(sbuf_t *buf);
sbuf_t *__wrap_sbufDuplicate(sbuf_t *buf);
sbuf_t *__wrap_sbufDuplicate(sbuf_t *buf)
{
    return twfTrackAcquired(__real_sbufDuplicate(buf));
}

sbuf_t *__real_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second);
sbuf_t *__wrap_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second);
sbuf_t *__wrap_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second)
{
    sbuf_t *merged = __real_sbufAppendMerge(pool, first, second);
    /* Internal disposal in buffer_pool.c bypasses the reuse linker wrapper. */
    twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, second);
    twfLedgerRemember(g_twf_buffers.recycled, &g_twf_buffers.recycled_count, second, "too many merged buffers");
    if (merged != first)
    {
        twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, first);
        twfTrackAcquired(merged);
    }
    return merged;
}

static sbuf_t *input(const void *data, uint32_t length, bool pipe)
{
#if WW_HAVE_SPLICE
    if (pipe)
    {
        /* Keep the private body within one page, independent of host pipe size. */
        const uint32_t body = min(length, 2048U), prefix = length - body;
        sbuf_t        *buf;
        if (prefix <= 128)
            buf = bufferpoolGetSpliceBuffer(env.pool);
        else
        {
            buf = twfTrackAcquired(sbufCreateSplice((uint16_t) (prefix + 128)));
            twfRequire(testSpliceSourceInitPipe(buf) == 0, "create resident-prefix pipe");
            buf->flags |= kSbufFlagSplice;
        }
        twfRequire(buf != NULL && prefix <= UINT16_MAX - 128, "create exclusive splice input");
        twfRequire(write(sbufSpliceMetadata(buf).pipefd[1], (const uint8_t *) data + prefix, body) == (ssize_t) body,
                   "populate private body");
        buf->capacity = buf->l_pad + body;
        sbufSetLength(buf, body);
        sbufShiftLeft(buf, prefix);
        memoryCopy(sbufGetMutablePtr(buf), data, prefix);
        return buf;
    }
#else
    discard pipe;
#endif
    sbuf_t *buf = bufferpoolGetBestFit(env.pool, length, 128);
    memoryCopy(sbufGetMutablePtr(buf), data, length);
    sbufSetLength(buf, length);
    return buf;
}

static void upstream(sbuf_t *buf)
{
    node->fnPayloadU(node, main_line, buf);
}

static void downstream(sbuf_t *buf)
{
#ifdef TEST_FISHER_SERVER
    node->fnPayloadD(node, main_line, buf);
#else
    node->fnPayloadD(node, children[0], buf);
#endif
}

static void handshake(sbuf_t *buf)
{
#ifdef TEST_FISHER_SERVER
    upstream(buf);
#else
    downstream(buf);
#endif
}

static void finish(tunnel_t *t, line_t *l)
{
    ++finishes[t == prev ? 1 : 0];
    if (t == prev)
        lineDestroy(l);
}

static void noop(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}

static void capture(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    const unsigned side          = t == prev ? 1 : 0;
    const uint32_t length        = sbufGetLength(buf);
    line_t        *expected_line = main_line;
#ifndef TEST_FISHER_SERVER
    if (! side)
        expected_line = children[0];
#endif
    twfRequire(l == expected_line, "payload crossed the wrong line role");
#ifdef TEST_FISHER_SERVER
    if (side && length == 5)
    {
        twfRequire(! sbufIsSplice(buf) && memcmp(sbufGetRawPtr(buf), "FISH!", 5) == 0, "probe reply changed");
        lineReuseBuffer(l, buf);
        if (nested)
        {
            nested = false;
            upstream(input("N", 1, WW_HAVE_SPLICE));
        }
        return;
    }
#endif
    if (expected_identity != NULL)
        twfRequire(buf == expected_identity, "ready relay replaced the owned payload");
    twfRequire(length <= sizeof(output[side]) - lengths[side], "capture overflow");
    ++calls[side];
    pipe_calls[side] += sbufIsSplice(buf);
    const bool saved = measuring;
    measuring        = false;
    sbufReadRangeToMemory(buf, output[side] + lengths[side], length);
    lineReuseBuffer(l, buf);
    measuring = saved;
    lengths[side] += length;
#ifndef TEST_FISHER_SERVER
    if (side && nested)
    {
        nested = false;
        downstream(input("N", 1, WW_HAVE_SPLICE));
    }
#endif
    if (close_output)
    {
        if (side)
        {
            node->fnFinU(node, l);
            lineDestroy(l);
        }
        else
            node->fnFinD(node, l);
    }
}

static void init(tunnel_t *t, line_t *l)
{
    discard t;
    ++inits;
    node->fnEstD(node, l);
    if (overflow_init)
    {
        for (unsigned i = 0; i < MAX_BUFFERS - 1; ++i)
            upstream(input("N", 1, false));
        twfRequire(lineIsAlive(l), "exact entry allowance rejected");
        upstream(input("X", 1, false));
    }
}

static void setup(void)
{
    memoryZero(lengths, sizeof(lengths));
    memoryZero(calls, sizeof(calls));
    memoryZero(pipe_calls, sizeof(pipe_calls));
    memoryZero(finishes, sizeof(finishes));
    measuring = nested = close_output = overflow_init = fail_queue = false;
    expected_identity                                              = NULL;
    reads = inits = 0;
    twfWorkerEnvSetup(&env, 8192, 128);
    metadata = nodeGet();
    twfRequire(metadata.flags == kNodeFlagSupportsSplice && metadata.required_padding_left == 0,
               "Fisher capability or padding changed");
    node = nodeCreate(&metadata);
    prev = tunnelCreate(NULL, 0, 0);
    next = tunnelCreate(NULL, 0, 0);
    twfRequire(node != NULL && prev != NULL && next != NULL, "construct Fisher fixture");
    tunnelBind(prev, node);
    tunnelBind(node, next);
    prev->fnFinD = next->fnFinU = finish;
    prev->fnEstD = prev->fnPauseD = prev->fnResumeD = next->fnPauseU = next->fnResumeU = noop;
    prev->fnPayloadD = next->fnPayloadU = capture;
    next->fnInitU                       = init;
    twfLinePoolSetup(&lines, node->lstate_size, 8);
    main_line = twfLinePoolCreateLine(&lines);
    lineRef(main_line);
#ifdef TEST_FISHER_SERVER
    node->fnInitU(node, main_line);
#else
    connectionfisherclient_lstate_t *main_ls = lineGetState(main_line, node);
    twfRequire(connectionfisherclientLinestateInitializeMain(main_ls, main_line, 3), "initialize main line");
    for (unsigned i = 0; i < 3; ++i)
    {
        children[i] = twfLinePoolCreateLine(&lines);
        lineRef(children[i]);
        connectionfisherclient_lstate_t *child = lineGetState(children[i], node);
        connectionfisherclientLinestateInitializeChild(child, children[i], main_line, i);
        child->ping_sent        = true;
        main_ls->child_lines[i] = children[i];
        ++main_ls->open_child_count;
    }
    lineMarkEstablished(children[0]);
#endif
}

static void teardown(void)
{
    fail_queue = false;
    if (lineIsAlive(main_line))
    {
        node->fnFinU(node, main_line);
        lineDestroy(main_line);
    }
    twfRequireLineStateZeroed(main_line, node, "Fisher retained main state");
    twfRequire(twfLineRefCount(main_line) == 1, "Fisher leaked main reference");
    lineUnref(main_line);
#ifndef TEST_FISHER_SERVER
    for (unsigned i = 0; i < 3; ++i)
    {
        twfRequire(! lineIsAlive(children[i]) && twfLineRefCount(children[i]) == 1, "Fisher leaked child line");
        twfRequireLineStateZeroed(children[i], node, "Fisher retained child state");
        lineUnref(children[i]);
    }
#endif
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&lines);
    tunnelDestroy(node);
    tunnelDestroy(prev);
    tunnelDestroy(next);
    memoryFree(metadata.type);
    twfWorkerEnvTeardown(&env);
}

static void checkRetired(void)
{
#ifdef TEST_FISHER_SERVER
    connectionfisherserver_lstate_t *ls = lineGetState(main_line, node);
    twfRequire(ls->phase == kConnectionFisherServerPhaseEstablished && ls->in_stream.pool == NULL &&
                   ww_sbuffer_queue_t_capacity(&ls->pending_up.q) == 0,
               "server retained setup storage");
#else
    connectionfisherclient_lstate_t *main_ls = lineGetState(main_line, node);
    connectionfisherclient_lstate_t *child   = lineGetState(children[0], node);
    twfRequire(main_ls->selected_child == children[0] && child->read_stream.pool == NULL &&
                   ww_sbuffer_queue_t_capacity(&main_ls->pending_up.q) == 0,
               "client retained setup storage");
    twfRequire(! lineIsAlive(children[1]) && ! lineIsAlive(children[2]), "selection retained losing children");
#endif
}

static void testStartupAndRelay(bool pipe)
{
    twfSetCase("fragmented probe, large coalesced body, nested FIFO, retirement and opaque relay");
    setup();
    uint8_t data[8197];
    memcpy(data, MARKER, 5);
    memset(data + 5, 'A', sizeof(data) - 5);
#ifndef TEST_FISHER_SERVER
    upstream(input("Q", 1, pipe));
#endif
    handshake(input(data, 2, pipe));
    nested = true;
    handshake(input(data + 2, sizeof(data) - 2, pipe));
    const unsigned side =
#ifdef TEST_FISHER_SERVER
        0;
#else
        1;
#endif
    twfRequire(lengths[side] == 8193 && memcmp(output[side], data + 5, 8192) == 0 && output[side][8192] == 'N',
               "coalesced body or nested input changed order");
#ifdef TEST_FISHER_SERVER
    twfRequire(pipe_calls[0] == (unsigned) WW_HAVE_SPLICE, "server materialized post-probe nested input");
#else
    twfRequire(lengths[0] == 1 && output[0][0] == 'Q' && pipe_calls[0] == (unsigned) (pipe && WW_HAVE_SPLICE),
               "client lost or materialized queued application input");
#endif
    checkRetired();
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        sbuf_t *buf       = input("opaque body", 11, pipe);
        expected_identity = buf;
        measuring         = true;
        if (direction)
            downstream(buf);
        else
            upstream(buf);
        twfRequire(reads == 0, "ready relay read private body");
        measuring         = false;
        expected_identity = NULL;
    }
    uint8_t *large = memoryAllocate(MAX_PENDING + 32);
    memset(large, 'L', MAX_PENDING + 32);
    sbuf_t *buf         = input(large, MAX_PENDING + 32, false);
    expected_identity   = buf;
    const size_t before = lengths[0];
    upstream(buf);
    twfRequire(lineIsAlive(main_line) && lengths[0] == before + MAX_PENDING + 32 &&
                   memcmp(output[0] + before, large, MAX_PENDING + 32) == 0,
               "ready payload was buffered under startup limit");
    memoryFree(large);
    teardown();
}

static void testLimitsAndClose(void)
{
    for (unsigned extra = 0; extra < 2; ++extra)
    {
        twfSetCase("coalesced application body has an inclusive 2 MiB allowance separate from marker");
        setup();
        const uint32_t length = 5 + MAX_PENDING + extra;
        uint8_t       *data   = memoryAllocate(length);
        memcpy(data, MARKER, 5);
        memset(data + 5, 'A', length - 5);
        handshake(input(data, 4, false));
        handshake(input(data + 4, length - 4, false));
        twfRequire(lineIsAlive(main_line) == ! extra, "coalesced body boundary changed");
        if (! extra)
            checkRetired();
        memoryFree(data);
        teardown();
    }
    twfSetCase("fragmented malformed probe closes and settles private buffers");
    setup();
    handshake(input("FI", 2, WW_HAVE_SPLICE));
    handshake(input("XXX", 3, WW_HAVE_SPLICE));
    twfRequire(! lineIsAlive(main_line), "invalid probe survived");
    teardown();
    twfSetCase("queue refusal settles submitted private buffer");
    setup();
    fail_queue = true;
#ifdef TEST_FISHER_SERVER
    handshake(input(MARKER, 5, WW_HAVE_SPLICE));
#else
    upstream(input("Q", 1, WW_HAVE_SPLICE));
#endif
    twfRequire(! lineIsAlive(main_line), "queue refusal retained live line");
    teardown();
    twfSetCase("pending entry limit includes the body retained across Init");
    setup();
#ifdef TEST_FISHER_SERVER
    overflow_init = true;
    handshake(input("FISH?A", 6, false));
#else
    for (unsigned i = 0; i < MAX_BUFFERS; ++i)
        upstream(input("Q", 1, false));
    twfRequire(lineIsAlive(main_line), "exact pending entry allowance rejected");
    upstream(input("X", 1, false));
#endif
    twfRequire(! lineIsAlive(main_line), "pending entry overflow survived");
    teardown();
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        twfSetCase("Finish during retired relay closes exact main and child roles");
        setup();
        handshake(input(MARKER, 5, false));
#ifdef TEST_FISHER_SERVER
        upstream(input("Q", 1, false));
#endif
        checkRetired();
        close_output = true;
        if (direction)
            downstream(input("body", 4, WW_HAVE_SPLICE));
        else
            upstream(input("body", 4, WW_HAVE_SPLICE));
        twfRequire(! lineIsAlive(main_line), "relay Finish retained live line");
        teardown();
    }
}

#ifndef TEST_FISHER_SERVER
static void testPausedBacklog(void)
{
    twfSetCase("selected child Pause retains private backlog until Resume and then retires its queue");
    setup();
    connectionfisherclient_lstate_t *child = lineGetState(children[0], node);
    child->next_paused                     = true;
    upstream(input("Q", 1, WW_HAVE_SPLICE));
    handshake(input(MARKER, 5, WW_HAVE_SPLICE));
    connectionfisherclient_lstate_t *main_ls = lineGetState(main_line, node);
    twfRequire(calls[0] == 0 && bufferqueueGetBufCount(&main_ls->pending_up) == 1 && child->read_stream.pool == NULL,
               "selection drained through Pause or retained the parser");
    node->fnResumeD(node, children[0]);
    twfRequire(lengths[0] == 1 && output[0][0] == 'Q' && pipe_calls[0] == (unsigned) WW_HAVE_SPLICE,
               "Resume lost or materialized the queued private body");
    checkRetired();
    teardown();
}
#endif

int main(void)
{
    testStartupAndRelay(false);
    testStartupAndRelay(WW_HAVE_SPLICE);
    testLimitsAndClose();
#ifndef TEST_FISHER_SERVER
    testPausedBacklog();
#endif
    return 0;
}
