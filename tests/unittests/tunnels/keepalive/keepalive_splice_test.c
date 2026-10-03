/*
 * Covers: keepalive splice; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: testWatchdogTimeout, testWatchdogReplies, testWatchdogPauseAndEst, testWatchdogSettings,
 * testLargeFrameBoundaries, testOrdinaryAndLarge, testEncodeCloseAndLimits, testControlAndRejection; the
 * driver lists the remaining cases
 * Checks: Assertion labels include: create large resident-prefix pipe; create splice input; populate
 * exclusive pipe; encoder replaced a complete splice body
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.keepaliveclient_no_splice_unit; waterwall.keepaliveclient_splice_unit;
 * waterwall.keepaliveserver_no_splice_unit; waterwall.keepaliveserver_splice_unit
 */
#include "fixtures/failure/tunnel_line_failure_harness.h"

#ifdef TEST_KEEPALIVE_SERVER
#include "KeepAliveServer/interface.h"
#include "KeepAliveServer/structure.h"
#define nodeGet         nodeKeepAliveServerGet
#define nodeCreate      keepaliveserverTunnelCreate
#define nodeState       keepaliveserver_lstate_t
#define framePrefix     kKeepAliveServerFramePrefixSize
#define reentryBytes    kKeepAliveServerMaxReentryBytes
#define encode(t, l, b) keepaliveserverTunnelDownStreamPayload(t, l, b)
#define decode(t, l, b) keepaliveserverTunnelUpStreamPayload(t, l, b)
#else
#include "KeepAliveClient/interface.h"
#include "KeepAliveClient/structure.h"
#define nodeGet         nodeKeepAliveClientGet
#define nodeCreate      keepaliveclientTunnelCreate
#define nodeState       keepaliveclient_lstate_t
#define framePrefix     kKeepAliveFramePrefixSize
#define reentryBytes    kKeepAliveMaxReentryBytes
#define encode(t, l, b) keepaliveclientTunnelUpStreamPayload(t, l, b)
#define decode(t, l, b) keepaliveclientTunnelDownStreamPayload(t, l, b)
#endif

#include <unistd.h>

enum
{
    kExpectedChunkBytes = 6U * 1024U * 1024U
};

static twf_worker_env_t env;
static twf_line_pool_t  lines;
static node_t           metadata;
static tunnel_t        *node, *prev, *next;
static tunnel_chain_t   chain;
static line_t          *line;
static uint8_t          wire[2 * kExpectedChunkBytes + 1024], plain[2 * kExpectedChunkBytes + 1024];
static size_t           wire_length, plain_length, measured_reads;
static unsigned         wire_calls, plain_calls, finishes, inits;
static bool             measuring, fail_stream, fail_queue, inject_encode, inject_decode, close_output, require_splice;
static sbuf_t          *expected_identity;
static bool             pause_output;
static unsigned         encode_overflow;
#ifndef TEST_KEEPALIVE_SERVER
static bool inject_pong;
#endif

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
#ifndef TEST_KEEPALIVE_SERVER
    if (inject_pong)
    {
        inject_pong          = false;
        const uint8_t pong[] = {0, 0, 0, 1, 3};
        decode(node, l, ordinary(pong, sizeof(pong)));
    }
#endif
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
            sbuf_t *pending = bufferpoolGetBestFit(env.pool, reentryBytes, 128);
            sbufSetLength(pending, reentryBytes);
            memoryZero(sbufGetMutablePtr(pending), sbufGetLength(pending));
            encode(node, l, pending);
            twfRequire(bufferqueueGetBufLen(&ls->write_reentry) == reentryBytes,
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
        const uint8_t nested[] = {0, 0, 0, 2, 1, 'B'};
        decode(node, l, ordinary(nested, sizeof(nested)));
    }
    if (close_output)
        closeFromOutput(l);
}

static void setupWithSettings(const char *settings)
{
    twfBufferLedgerReset();
    wire_length = plain_length = measured_reads = 0;
    wire_calls = plain_calls = finishes = inits = 0;
    measuring = inject_encode = inject_decode = close_output = require_splice = false;
    pause_output                                                              = false;
    encode_overflow                                                           = 0;
    expected_identity                                                         = NULL;
#ifndef TEST_KEEPALIVE_SERVER
    inject_pong = false;
#endif
    twfWorkerEnvSetupWithBufferSizes(&env, 8192, 1024, 128, 65536, 65536);
    metadata                    = nodeGet();
    metadata.node_settings_json = settings != NULL ? cJSON_Parse(settings) : NULL;
    twfRequire(metadata.flags == kNodeFlagSupportsSplice && metadata.required_padding_left == framePrefix,
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
    prev->fnEstD                = noop;
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

static void setup(void)
{
    setupWithSettings(NULL);
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
    keepaliveclientTunnelOnWorkerQuiesce(node, 0, wwLifecycleProcessShutdown());
    keepaliveclientTunnelDestroy(node, wwLifecycleProcessShutdown());
#endif
    cJSON_Delete(metadata.node_settings_json);
    memoryFree(metadata.type);
    twfWorkerEnvTeardown(&env);
}

#ifndef TEST_KEEPALIVE_SERVER
static void setTime(uint64_t now)
{
    env.loop->cur_hrtime = now * 1000U;
}

static wtimer_t *watchdogSetup(bool establish)
{
    setupWithSettings("{\"ping-interval\":10,\"sensitive-mode\":true,\"tolerance-ms\":30}");
    keepaliveclient_tstate_t *ts    = tunnelGetState(node);
    wtimer_t                 *timer = wtimerAdd(env.loop, keepaliveclientWorkerTimerCallback, 10, INFINITE);
    twfRequire(timer != NULL, "create watchdog fixture timer");
    weventSetUserData(timer, node);
    ts->worker_timers[0] = timer;
    setTime(1000);
    if (establish)
        node->fnEstD(node, line);
    return timer;
}

static void tick(wtimer_t *timer, uint64_t now)
{
    setTime(now);
    keepaliveclientWorkerTimerCallback(timer);
}

static void testWatchdogTimeout(void)
{
    wtimer_t *timer = watchdogSetup(true);
    tick(timer, 1010);
    twfRequire(wire_calls == 1 && memoryCompare(wire, "\0\0\0\1\2", 5) == 0, "watchdog did not send ping");
    const uint8_t partial[] = {0, 0, 0, 5, 1, 'A'};
#if WW_HAVE_SPLICE
    decode(node, line, pipeBytes(partial, sizeof(partial), 0));
#else
    decode(node, line, ordinary(partial, sizeof(partial)));
#endif
    tick(timer, 1039);
    twfRequire(lineIsAlive(line), "watchdog expired before tolerance");
    tick(timer, 1040);
    twfRequire(! lineIsAlive(line) && finishes == 2, "missing pong did not close borrowed connection");
    twfRequire(wire_calls == 1, "watchdog sent another ping while awaiting a reply");
    teardown();
}

static void testWatchdogReplies(void)
{
    const uint8_t pong[] = {0, 0, 0, 1, 3};
    wtimer_t     *timer  = watchdogSetup(true);
    tick(timer, 1009);
    twfRequire(wire_calls == 0, "watchdog ping escaped interval");
    tick(timer, 1010);
    setTime(1015);
    for (unsigned i = 0; i < sizeof(pong); ++i)
    {
#if WW_HAVE_SPLICE
        decode(node, line, i % 2 ? ordinary(pong + i, 1) : pipeBytes(pong + i, 1, 0));
#else
        decode(node, line, ordinary(pong + i, 1));
#endif
    }
    node->fnEstD(node, line); /* Repeated Est must not postpone the next ping. */
    tick(timer, 1019);
    twfRequire(wire_calls == 1, "timely pong accelerated the ping interval");
    tick(timer, 1020);
    twfRequire(wire_calls == 2 && lineIsAlive(line), "timely pong did not release next ping");
    const uint8_t other[] = {0, 0, 0, 2, 3, 'X', 0, 0, 0, 2, 1, 'A', 0, 0, 0, 1, 2};
    setTime(1025);
    decode(node, line, ordinary(other, sizeof(other)));
    tick(timer, 1050);
    twfRequire(! lineIsAlive(line) && finishes == 2 && plain_length == 1 && wire_calls == 3,
               "normal traffic, peer ping or nonempty pong satisfied watchdog");
    teardown();

    timer = watchdogSetup(true);
    tick(timer, 1010);
    setTime(1040);
    decode(node, line, ordinary(pong, sizeof(pong)));
    twfRequire(! lineIsAlive(line) && finishes == 2, "late pong bypassed the reply deadline");
    teardown();

    timer       = watchdogSetup(true);
    inject_pong = true;
    tick(timer, 1010);
    tick(timer, 1020);
    twfRequire(wire_calls == 2 && lineIsAlive(line), "reentrant pong was lost before ping state was published");
    close_output = true;
    setTime(1025);
    decode(node, line, ordinary(pong, sizeof(pong)));
    tick(timer, 1030);
    twfRequire(! lineIsAlive(line) && wire_calls == 3, "watchdog continued after ping callback closed line");
    teardown();
}

static void testWatchdogPauseAndEst(void)
{
    wtimer_t *timer = watchdogSetup(false);
    tick(timer, 2000);
    twfRequire(wire_calls == 0 && lineIsAlive(line), "watchdog ran before transport Est");
    node->fnEstD(node, line);
    tick(timer, 2010);
    twfRequire(wire_calls == 1, "watchdog did not start after Est");
    setTime(2020);
    node->fnPauseD(node, line);
    setTime(2030);
    node->fnPauseD(node, line);
    setTime(2035);
    node->fnPauseU(node, line);
    tick(timer, 2039);
    twfRequire(lineIsAlive(line) && wire_calls == 1, "paused watchdog expired before its deadline");
    tick(timer, 2040);
    twfRequire(! lineIsAlive(line) && finishes == 2, "Pause postponed the watchdog deadline");
    teardown();

    timer = watchdogSetup(true);
    setTime(1005);
    node->fnPauseU(node, line);
    node->fnPauseD(node, line);
    tick(timer, 1010);
    twfRequire(wire_calls == 1 && lineIsAlive(line), "Pause suppressed a due watchdog ping");
    const uint8_t pong[] = {0, 0, 0, 1, 3};
    setTime(1015);
    decode(node, line, ordinary(pong, sizeof(pong)));
    tick(timer, 1020);
    twfRequire(wire_calls == 2 && lineIsAlive(line), "paused watchdog lost Pong or stopped its ping interval");
    setTime(1030);
    node->fnResumeD(node, line);
    tick(timer, 1049);
    twfRequire(lineIsAlive(line), "partial Resume shortened the watchdog deadline");
    tick(timer, 1050);
    twfRequire(! lineIsAlive(line) && finishes == 2, "overlapping Pause or Resume extended the watchdog deadline");
    teardown();
}

static void testWatchdogSettings(void)
{
    setupWithSettings("{\"ping-interval\":10,\"tolerance-ms\":30,\"sensitive-mode\":false}");
    const char *invalid[] = {"{\"tolerance-ms\":0}",
                             "{\"tolerance-ms\":-1}",
                             "{\"sensitive-mode\":\"yes\"}",
                             "{\"tolerance-ms\":\"30\"}",
                             "{\"tolerance-ms\":1.5}",
                             "{\"tolerance-ms\":2147483648}"};
    for (unsigned i = 0; i < ARRAY_SIZE(invalid); ++i)
    {
        node_t config             = nodeGet();
        config.node_settings_json = cJSON_Parse(invalid[i]);
        tunnel_t *candidate       = nodeCreate(&config);
        twfRequire(candidate == NULL, "watchdog accepted invalid settings");
        cJSON_Delete(config.node_settings_json);
        memoryFree(config.type);
    }
    wtimer_t *timer = wtimerAdd(env.loop, keepaliveclientWorkerTimerCallback, 10, INFINITE);
    twfRequire(timer != NULL, "create disabled watchdog timer");
    weventSetUserData(timer, node);
    ((keepaliveclient_tstate_t *) tunnelGetState(node))->worker_timers[0] = timer;
    node->fnPauseU(node, line);
    node->fnPauseD(node, line);
    tick(timer, 1000);
    tick(timer, 1000000);
    twfRequire(lineIsAlive(line) && wire_calls == 2, "Pause suppressed pings with the reply watchdog disabled");
    teardown();
    setup();
    const keepaliveclient_tstate_t *ts = tunnelGetState(node);
    twfRequire(! ts->sensitive_mode && ts->tolerance_ms == 90000 && ts->ping_interval_ms == 30000,
               "incorrect watchdog defaults");
    teardown();
}
#endif

static void testLargeFrameBoundaries(void)
{
    const uint32_t lengths[] = {
        kExpectedChunkBytes - 1, kExpectedChunkBytes, kExpectedChunkBytes + 1, 2 * kExpectedChunkBytes + 17};
    for (unsigned test = 0; test < ARRAY_SIZE(lengths); ++test)
    {
        setup();
        uint32_t length  = lengths[test];
        uint8_t *payload = memoryAllocate(length);
        for (uint32_t i = 0; i < length; ++i)
            payload[i] = (uint8_t) (i * 31);
        encode(node, line, ordinary(payload, length));
        unsigned frames = (length + kExpectedChunkBytes - 1) / kExpectedChunkBytes;
        twfRequire(wire_calls == frames, "encoder did not use the 6 MiB chunk boundary");
        twfRequire(framePrefix == 5 && wire_length == length + 5 * frames, "incorrect large-frame prefix size");
        size_t   offset    = 0;
        uint32_t remaining = length;
        while (remaining != 0)
        {
            uint32_t network_length;
            memoryCopy(&network_length, wire + offset, sizeof(network_length));
            uint32_t chunk = min(remaining, (uint32_t) kExpectedChunkBytes);
            twfRequire(ntohl(network_length) == chunk + 1 && wire[offset + 4] == 1,
                       "incorrect 32-bit frame length or kind");
            offset += chunk + 5;
            remaining -= chunk;
        }
        for (size_t cursor = 0; cursor < wire_length;)
        {
            uint32_t count = (uint32_t) min(wire_length - cursor, 128U * 1024U);
            decode(node, line, ordinary(wire + cursor, count));
            cursor += count;
        }
        twfRequire(plain_length == length && plain_calls == frames && memoryCompare(plain, payload, length) == 0,
                   "fragmented large frames changed payload or frame boundaries");
        memoryFree(payload);
        teardown();
    }
}

static void testOrdinaryAndLarge(void)
{
    setup();
    uint8_t *payload = memoryAllocate(200000);
    for (uint32_t i = 0; i < 200000; ++i)
        payload[i] = (uint8_t) (i * 31);
    inject_encode = true;
    encode(node, line, ordinary(payload, 200000));
    twfRequire(wire_calls == 2, "large encode or nested input lost a frame");
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
    uint8_t *payload = memoryAllocate(kExpectedChunkBytes + 200000);
    memoryZero(payload, kExpectedChunkBytes + 200000);
    encode(node, line, ordinary(payload, kExpectedChunkBytes + 200000));
    memoryFree(payload);
    twfRequire(! lineIsAlive(line) && wire_calls == 1, "large encoder continued or retained suffix after close");
    teardown();

    for (unsigned mode = 1; mode <= 3; ++mode)
    {
        setup();
        encode_overflow = mode;
        if (mode == 3)
        {
            payload = memoryAllocate(kExpectedChunkBytes + 200000);
            memoryZero(payload, kExpectedChunkBytes + 200000);
            encode(node, line, ordinary(payload, kExpectedChunkBytes + 200000));
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
    const uint8_t controls[] = {0, 0, 0, 1, 2, 0, 0, 0, 1, 3, 0, 0, 0, 2, 9, 'X', 0, 0, 0, 1, 1};
    for (unsigned i = 0; i < sizeof(controls); ++i)
        decode(node, line, ordinary(controls + i, 1));
    twfRequire(plain_calls == 0 && wire_length == 5 && memoryCompare(wire, "\0\0\0\1\3", 5) == 0,
               "ping, pong, unknown or empty normal frame changed behavior");
#ifndef TEST_KEEPALIVE_SERVER
    node->fnPauseD(node, line);
    twfRequire(keepaliveclientSendPingFrame(node, line) && wire_calls == 2, "Pause suppressed the timer ping");
    node->fnResumeD(node, line);
    twfRequire(keepaliveclientSendPingFrame(node, line) && wire_calls == 3, "Resume changed regular ping behavior");
#endif
    const uint8_t invalid[] = {0, 0, 0, 0, 1};
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

    const uint32_t rejected[] = {kExpectedChunkBytes + 2, UINT32_MAX};
    for (unsigned i = 0; i < ARRAY_SIZE(rejected); ++i)
    {
        setup();
        uint8_t  header[5];
        uint32_t network_length = htonl(rejected[i]);
        memoryCopy(header, &network_length, sizeof(network_length));
        header[4] = 1;
        decode(node, line, ordinary(header, 4));
        twfRequire(lineIsAlive(line), "partial wide header was rejected before the kind arrived");
        decode(node, line, ordinary(header + 4, 1));
        twfRequire(! lineIsAlive(line) && plain_calls == 0 && finishes == 2,
                   "oversized frame length waited for a body or escaped validation");
        teardown();
    }
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
    twfRequire(measured_reads == 0 && wire_length == sizeof(payload) + 5, "encode read the pipe body");
    measured_reads = 0;
    decode(node, line, pipeBytes(wire, (uint32_t) wire_length, 0));
    twfRequire(measured_reads == 5 && plain_length == sizeof(payload) &&
                   memoryCompare(plain, payload, sizeof(payload)) == 0,
               "decoder read more than its fixed header or changed payload");
    teardown();

    /* Split headers and bodies alternate between ordinary and private-pipe inputs. */
    setup();
    const uint8_t fragments[] = {0, 0, 0, 5, 1, 'A', 'B', 'C', 'D', 0, 0, 0, 2, 1, 'E'};
    for (unsigned i = 0; i < sizeof(fragments); ++i)
        decode(node, line, i % 2 ? ordinary(fragments + i, 1) : pipeBytes(fragments + i, 1, 0));
    twfRequire(plain_length == 5 && memoryCompare(plain, "ABCDE", 5) == 0, "mixed fragmented frames changed order");
    teardown();

    /* A 68,000-byte resident-prefix/pipe payload now fits one frame unchanged. */
    setup();
    uint8_t *large = memoryAllocate(68000);
    for (unsigned i = 0; i < 68000; ++i)
        large[i] = (uint8_t) i;
    measuring = true;
    encode(node, line, pipeBytes(large, 68000, 60000));
    twfRequire(wire_calls == 1 && wire_length == 68005 && measured_reads == 0,
               "large splice input did not stay in one frame");
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
    decode(node, line, pipeBytes(fragments, 6, 0));
    twfRequire(plain_calls == 0, "incomplete splice body escaped");
    teardown();
}

static void testLargePipeFrame(void)
{
    setup();
    uint8_t *payload = memoryAllocate(kExpectedChunkBytes);
    for (uint32_t i = 0; i < kExpectedChunkBytes; ++i)
        payload[i] = (uint8_t) (i * 17);
    encode(node, line, ordinary(payload, kExpectedChunkBytes));
    twfRequire(wire_calls == 1, "maximum payload did not produce one frame");
    measuring = true;
    for (size_t offset = 0; offset < wire_length;)
    {
        uint32_t bytes = (uint32_t) min(wire_length - offset, 8192U);
        decode(node, line, pipeBytes(wire + offset, bytes, 0));
        offset += bytes;
        if (offset != wire_length)
            twfRequire(plain_calls == 0 && lineIsAlive(line), "partial maximum pipe frame escaped or closed");
    }
    twfRequire(plain_calls == 1 && plain_length == kExpectedChunkBytes &&
                   memoryCompare(plain, payload, kExpectedChunkBytes) == 0,
               "maximum frame from many pipes changed bytes");
    /* The fixture requests 64 KiB pipes, so a complete 6 MiB body must use ordinary fallback. */
    twfRequire(measured_reads == wire_length, "large pipe-pressure fallback did not settle all bytes exactly once");
    memoryFree(payload);
    teardown();
}
#endif

int main(void)
{
#ifndef TEST_KEEPALIVE_SERVER
    testWatchdogTimeout();
    testWatchdogReplies();
    testWatchdogPauseAndEst();
    testWatchdogSettings();
#endif
    testLargeFrameBoundaries();
    testOrdinaryAndLarge();
    testControlAndRejection();
    testEncodeCloseAndLimits();
#if WW_HAVE_SPLICE
    testPipes();
    testLargePipeFrame();
#endif
    puts("KeepAlive frame bytes, splice ownership, FIFO and close tests passed");
    return 0;
}
