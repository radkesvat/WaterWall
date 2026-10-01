#include "tunnel_line_failure_harness.h"

#ifdef TEST_KEEPALIVE_SERVER
#include "KeepAliveServer/interface.h"
#include "KeepAliveServer/structure.h"
#define nodeGet         nodeKeepAliveServerGet
#define nodeCreate      keepaliveserverTunnelCreate
#define nodeState       keepaliveserver_lstate_t
#define encode(t, l, b) keepaliveserverTunnelDownStreamPayload(t, l, b)
#define decode(t, l, b) keepaliveserverTunnelUpStreamPayload(t, l, b)
#else
#include "KeepAliveClient/interface.h"
#include "KeepAliveClient/structure.h"
#define nodeGet         nodeKeepAliveClientGet
#define nodeCreate      keepaliveclientTunnelCreate
#define nodeState       keepaliveclient_lstate_t
#define encode(t, l, b) keepaliveclientTunnelUpStreamPayload(t, l, b)
#define decode(t, l, b) keepaliveclientTunnelDownStreamPayload(t, l, b)
#endif

#include <unistd.h>

static twf_worker_env_t env;
static twf_line_pool_t  lines;
static node_t           metadata;
static tunnel_t        *node, *prev, *next;
static tunnel_chain_t   chain;
static line_t          *line;
static uint8_t          wire[3 * 1024 * 1024], plain[3 * 1024 * 1024];
static size_t           wire_length, plain_length, measured_reads;
static unsigned         wire_calls, plain_calls, finishes, inits;
static bool             measuring, fail_stream, fail_queue, inject_encode, inject_decode, close_output, require_splice;
static sbuf_t          *expected_identity;
static bool             pause_output;
static unsigned         encode_overflow;

ssize_t __real_read(int fd, void *destination, size_t bytes);
ssize_t __wrap_read(int fd, void *destination, size_t bytes);
ssize_t __wrap_read(int fd, void *destination, size_t bytes)
{
    ssize_t result = __real_read(fd, destination, bytes);
    if (measuring && result > 0)
        measured_reads += (size_t) result;
    return result;
}

splice_stream_t *__real_splicestreamCreate(buffer_pool_t *pool, uint32_t header_size);
splice_stream_t *__wrap_splicestreamCreate(buffer_pool_t *pool, uint32_t header_size);
splice_stream_t *__wrap_splicestreamCreate(buffer_pool_t *pool, uint32_t header_size)
{
    return fail_stream ? NULL : __real_splicestreamCreate(pool, header_size);
}

bool __real_bufferqueueReserveExtra(buffer_queue_t *queue, size_t extra);
bool __wrap_bufferqueueReserveExtra(buffer_queue_t *queue, size_t extra);
bool __wrap_bufferqueueReserveExtra(buffer_queue_t *queue, size_t extra)
{
    return ! fail_queue && __real_bufferqueueReserveExtra(queue, extra);
}

static sbuf_t *ordinary(const void *data, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetBestFit(env.pool, length, 128);
    sbufSetLength(buf, length);
    memoryCopy(sbufGetMutablePtr(buf), data, length);
    return buf;
}

#if WW_HAVE_SPLICE
static sbuf_t *pipeBytes(const void *data, uint32_t length, uint32_t prefix)
{
    const uint8_t *bytes = data;
    sbuf_t        *buf;
    if (prefix <= 128)
        buf = bufferpoolGetSpliceBuffer(env.pool);
    else
    {
        buf = twfTrackAcquired(sbufCreateSplice((uint16_t) (prefix + 128)));
        twfRequire(sbufSpliceInitPipe(buf, 8192) == 0, "create large resident-prefix pipe");
        buf->flags |= kSbufFlagSplice;
    }
    twfRequire(buf != NULL && prefix <= length, "create splice input");
    uint32_t body = length - prefix;
    twfRequire(write(sbufSpliceMetadata(buf).pipefd[1], bytes + prefix, body) == (ssize_t) body,
               "populate exclusive pipe");
    buf->capacity = buf->l_pad + body;
    sbufSetLength(buf, body);
    sbufShiftLeft(buf, prefix);
    memoryCopy(sbufGetMutablePtr(buf), bytes, prefix);
    return buf;
}
#endif

static void noop(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}

static void init(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++inits;
}

static void finish(tunnel_t *t, line_t *l)
{
    ++finishes;
    if (t == prev)
        lineDestroy(l);
}

static void closeFromOutput(line_t *l)
{
    /* The previous endpoint owns this normal line; close toward next only. */
    node->fnFinU(node, l);
    lineDestroy(l);
}

static void captureWire(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    if (expected_identity != NULL)
        twfRequire(buf == expected_identity, "encoder replaced a complete splice body");
    if (require_splice)
        twfRequire(sbufIsSplice(buf), "encoder materialized a feasible pipe body");
    size_t length = sbufGetLength(buf);
    twfRequire(length <= sizeof(wire) - wire_length, "wire capture overflow");
    bool saved = measuring;
    measuring  = false;
    sbufReadRangeToMemory(buf, wire + wire_length, (uint32_t) length);
    measuring = saved;
    wire_length += length;
    ++wire_calls;
    lineReuseBuffer(l, buf);
    if (inject_encode)
    {
        inject_encode = false;
        encode(node, l, ordinary("Z", 1));
    }
    if (encode_overflow != 0)
    {
        unsigned mode   = encode_overflow;
        encode_overflow = 0;
        nodeState *ls   = lineGetState(l, node);
        if (mode == 1)
        {
            sbuf_t *pending = bufferpoolGetBestFit(env.pool, 2 * 1024 * 1024, 128);
            sbufSetLength(pending, 2 * 1024 * 1024);
            memoryZero(sbufGetMutablePtr(pending), sbufGetLength(pending));
            encode(node, l, pending);
            twfRequire(bufferqueueGetBufLen(&ls->write_reentry) == 2 * 1024 * 1024,
                       "encoder refused exact reentry byte limit");
        }
        else
        {
            unsigned queued = mode == 3 ? 1023 : 1024;
            for (unsigned i = 0; i < queued; ++i)
                encode(node, l, ordinary("Q", 1));
            twfRequire(bufferqueueGetBufCount(&ls->write_reentry) == queued && (mode != 3 || ls->write_active != NULL),
                       "encoder refused exact reentry entry limit");
        }
        encode(node, l, ordinary("X", 1));
    }
    if (close_output)
        closeFromOutput(l);
}

static void capturePlain(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    if (require_splice)
        twfRequire(sbufIsSplice(buf), "decoder materialized a feasible pipe body");
    size_t length = sbufGetLength(buf);
    twfRequire(length <= sizeof(plain) - plain_length, "payload capture overflow");
    bool saved = measuring;
    measuring  = false;
    sbufReadRangeToMemory(buf, plain + plain_length, (uint32_t) length);
    measuring = saved;
    plain_length += length;
    ++plain_calls;
    lineReuseBuffer(l, buf);
    if (pause_output)
    {
#ifdef TEST_KEEPALIVE_SERVER
        node->fnPauseD(node, l);
#else
        node->fnPauseU(node, l);
#endif
    }
    if (inject_decode)
    {
        inject_decode          = false;
        const uint8_t nested[] = {0, 2, 1, 'B'};
        decode(node, l, ordinary(nested, sizeof(nested)));
    }
    if (close_output)
        closeFromOutput(l);
}

static void setup(void)
{
    twfBufferLedgerReset();
    wire_length = plain_length = measured_reads = 0;
    wire_calls = plain_calls = finishes = inits = 0;
    measuring = inject_encode = inject_decode = close_output = require_splice = false;
    pause_output                                                              = false;
    encode_overflow                                                           = 0;
    expected_identity                                                         = NULL;
    twfWorkerEnvSetupWithBufferSizes(&env, 8192, 1024, 128, 65536, 65536);
    metadata = nodeGet();
    twfRequire(metadata.flags == kNodeFlagSupportsSplice && metadata.required_padding_left == 3,
               "incorrect KeepAlive metadata");
    node = nodeCreate(&metadata);
    prev = tunnelCreate(NULL, 0, 0);
    next = tunnelCreate(NULL, 0, 0);
    twfRequire(node != NULL && prev != NULL && next != NULL, "construct KeepAlive fixture");
    tunnelBind(prev, node);
    tunnelBind(node, next);
    memoryZero(&chain, sizeof(chain));
    chain.supports_splice = WW_HAVE_SPLICE;
    node->chain           = &chain;
    prev->fnFinD = next->fnFinU = finish;
    next->fnInitU               = init;
    prev->fnPauseD = prev->fnResumeD = next->fnPauseU = next->fnResumeU = noop;
#ifdef TEST_KEEPALIVE_SERVER
    prev->fnPayloadD = captureWire;
    next->fnPayloadU = capturePlain;
#else
    next->fnPayloadU = captureWire;
    prev->fnPayloadD = capturePlain;
#endif
    twfLinePoolSetup(&lines, node->lstate_size, 4);
    line = twfLinePoolCreateLine(&lines);
    lineRef(line);
    node->fnInitU(node, line);
}

static void teardown(void)
{
    fail_stream = fail_queue = false;
    if (lineIsAlive(line))
    {
        node->fnFinU(node, line);
        lineDestroy(line);
    }
    twfRequireLineStateZeroed(line, node, "KeepAlive retained line state");
    twfRequireEqualU32(twfLineRefCount(line), 1, "KeepAlive leaked line references");
    lineUnref(line);
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&lines);
    tunnelDestroy(prev);
    tunnelDestroy(next);
#ifdef TEST_KEEPALIVE_SERVER
    tunnelDestroy(node);
#else
    keepaliveclientTunnelDestroy(node, wwLifecycleProcessShutdown());
#endif
    memoryFree(metadata.type);
    twfWorkerEnvTeardown(&env);
}

static void testOrdinaryAndLarge(void)
{
    setup();
    uint8_t *payload = memoryAllocate(200000);
    for (uint32_t i = 0; i < 200000; ++i)
        payload[i] = (uint8_t) (i * 31);
    inject_encode = true;
    encode(node, line, ordinary(payload, 200000));
    twfRequire(wire_calls == 5, "large encode or nested input lost a frame");
    inject_decode = true;
    pause_output  = true;
    decode(node, line, ordinary(wire, (uint32_t) wire_length));
    twfRequire(plain_length == 200002 && memoryCompare(plain, payload, 200000) == 0 && plain[200000] == 'Z' &&
                   plain[200001] == 'B',
               "large coalesced delivery or reentrant FIFO changed bytes");
    memoryFree(payload);
    teardown();
}

static void testEncodeCloseAndLimits(void)
{
    setup();
    close_output     = true;
    uint8_t *payload = memoryAllocate(200000);
    memoryZero(payload, 200000);
    encode(node, line, ordinary(payload, 200000));
    memoryFree(payload);
    twfRequire(! lineIsAlive(line) && wire_calls == 1, "large encoder continued or retained suffix after close");
    teardown();

    for (unsigned mode = 1; mode <= 3; ++mode)
    {
        setup();
        encode_overflow = mode;
        if (mode == 3)
        {
            payload = memoryAllocate(200000);
            memoryZero(payload, 200000);
            encode(node, line, ordinary(payload, 200000));
            memoryFree(payload);
        }
        else
            encode(node, line, ordinary("A", 1));
        twfRequire(! lineIsAlive(line) && wire_calls == 1 && finishes == 2,
                   "encoder overflow did not close and dispose queued input");
        teardown();
    }
}

static void testControlAndRejection(void)
{
    setup();
    const uint8_t controls[] = {0, 1, 2, 0, 1, 3, 0, 2, 9, 'X', 0, 1, 1};
    for (unsigned i = 0; i < sizeof(controls); ++i)
        decode(node, line, ordinary(controls + i, 1));
    twfRequire(plain_calls == 0 && wire_length == 3 && memoryCompare(wire, "\0\1\3", 3) == 0,
               "ping, pong, unknown or empty normal frame changed behavior");
#ifndef TEST_KEEPALIVE_SERVER
    node->fnPauseD(node, line);
    twfRequire(keepaliveclientSendPingFrame(node, line) && wire_calls == 1, "timer ping escaped Pause");
    node->fnResumeD(node, line);
    twfRequire(keepaliveclientSendPingFrame(node, line) && wire_calls == 2, "timer ping did not resume");
#endif
    const uint8_t invalid[] = {0, 0, 1};
    decode(node, line, ordinary(invalid, sizeof(invalid)));
    twfRequire(! lineIsAlive(line) && finishes == 2, "invalid frame did not close both directions");
    teardown();

    fail_stream = true;
    setup();
    twfRequire(! lineIsAlive(line) && inits == 0 && finishes == 1, "stream allocation failure reached next Init");
    teardown();

    setup();
    fail_queue = true;
    decode(node, line, ordinary(controls, 1));
    twfRequire(! lineIsAlive(line) && finishes == 2, "read admission failure did not close the line");
    teardown();
}

#if WW_HAVE_SPLICE
static void testPipes(void)
{
    setup();
    uint8_t payload[4096];
    for (unsigned i = 0; i < sizeof(payload); ++i)
        payload[i] = (uint8_t) i;
    require_splice = measuring = true;
    expected_identity          = pipeBytes(payload, sizeof(payload), 5);
    encode(node, line, expected_identity);
    expected_identity = NULL;
    twfRequire(measured_reads == 0 && wire_length == sizeof(payload) + 3, "encode read the pipe body");
    measured_reads = 0;
    decode(node, line, pipeBytes(wire, (uint32_t) wire_length, 0));
    twfRequire(measured_reads == 3 && plain_length == sizeof(payload) &&
                   memoryCompare(plain, payload, sizeof(payload)) == 0,
               "decoder read more than its fixed header or changed payload");
    teardown();

    /* Split headers and bodies alternate between ordinary and private-pipe inputs. */
    setup();
    const uint8_t fragments[] = {0, 5, 1, 'A', 'B', 'C', 'D', 0, 2, 1, 'E'};
    for (unsigned i = 0; i < sizeof(fragments); ++i)
        decode(node, line, i % 2 ? ordinary(fragments + i, 1) : pipeBytes(fragments + i, 1, 0));
    twfRequire(plain_length == 5 && memoryCompare(plain, "ABCDE", 5) == 0, "mixed fragmented frames changed order");
    teardown();

    /* A resident prefix plus a real body exceeds one frame without needing a huge kernel pipe. */
    setup();
    uint8_t *large = memoryAllocate(68000);
    for (unsigned i = 0; i < 68000; ++i)
        large[i] = (uint8_t) i;
    measuring = true;
    encode(node, line, pipeBytes(large, 68000, 60000));
    twfRequire(wire_calls == 2 && wire_length == 68006, "large splice input was not split");
    /* Destination pressure may choose ordinary fallback; wire bytes must always be exact. */
    decode(node, line, ordinary(wire, (uint32_t) wire_length));
    twfRequire(plain_length == 68000 && memoryCompare(plain, large, 68000) == 0, "splice splitting changed bytes");
    memoryFree(large);
    teardown();

    setup();
    close_output = true;
    encode(node, line, pipeBytes(fragments, sizeof(fragments), 2));
    twfRequire(! lineIsAlive(line) && wire_calls == 1, "encoder continued after callback close");
    teardown();

    setup();
    close_output = true;
    decode(node, line, pipeBytes(fragments, sizeof(fragments), 2));
    twfRequire(! lineIsAlive(line) && plain_calls == 1, "decoder continued after callback close");
    teardown();

    setup();
    decode(node, line, pipeBytes(fragments, 4, 0));
    twfRequire(plain_calls == 0, "incomplete splice body escaped");
    teardown();
}
#endif

int main(void)
{
    testOrdinaryAndLarge();
    testControlAndRejection();
    testEncodeCloseAndLimits();
#if WW_HAVE_SPLICE
    testPipes();
#endif
    puts("KeepAlive frame bytes, splice ownership, FIFO and close tests passed");
    return 0;
}
