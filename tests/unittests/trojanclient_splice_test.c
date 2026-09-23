#include "TrojanClient/interface.h"
#include "structure.h"
/* Keep the normal ownership ledger while refusing one first-output allocation. */
#define __wrap_bufferpoolTryGetBestFit trackedTryGetBestFit
#include "tunnel_line_failure_harness.h"
#undef __wrap_bufferpoolTryGetBestFit

static bool fail_initial_allocation;
sbuf_t     *__wrap_bufferpoolTryGetBestFit(buffer_pool_t *pool, uint64_t size, uint16_t padding);
sbuf_t     *__wrap_bufferpoolTryGetBestFit(buffer_pool_t *pool, uint64_t size, uint16_t padding)
{
    if (fail_initial_allocation)
    {
        fail_initial_allocation = false;
        return NULL;
    }
    return trackedTryGetBestFit(pool, size, padding);
}
#include "wloop_internal.h"

#if WW_HAVE_SPLICE
#include <fcntl.h>
#include <unistd.h>
#endif

static bool     fail_queue;
static bool     fail_pipe, pressure, reject_growth;
static unsigned moves, pipe_refusals, growth_refusals;
static size_t   reads;
bool            __real_bufferqueueTryPushBack(buffer_queue_t *, sbuf_t **);
bool            __wrap_bufferqueueTryPushBack(buffer_queue_t *, sbuf_t **);
bool            __wrap_bufferqueueTryPushBack(buffer_queue_t *q, sbuf_t **n)
{
    if (fail_queue)
    {
        fail_queue = false;
        return false;
    }
    return __real_bufferqueueTryPushBack(q, n);
}
#if WW_HAVE_SPLICE
int __real_pipe2(int *, int);
int __wrap_pipe2(int *, int);
int __wrap_pipe2(int *fds, int flags)
{
    if (fail_pipe)
    {
        ++pipe_refusals;
        errno = EMFILE;
        return -1;
    }
    int result = __real_pipe2(fds, flags);
    if (result == 0 && reject_growth)
        twfRequire(fcntl(fds[0], F_SETPIPE_SZ, 4096) == 4096, "one-page pipe setup failed");
    return result;
}
int __real_fcntl(int, int, ...);
int __wrap_fcntl(int, int, ...);
int __wrap_fcntl(int fd, int command, ...)
{
    if (command == F_GETPIPE_SZ || command == F_GETFD || command == F_GETFL)
        return __real_fcntl(fd, command);
    va_list args;
    va_start(args, command);
    int value = va_arg(args, int);
    va_end(args);
    if (command == F_SETPIPE_SZ && reject_growth && value > 4096)
    {
        ++growth_refusals;
        errno = EPERM;
        return -1;
    }
    return __real_fcntl(fd, command, value);
}
ssize_t __real_splice(int, off_t *, int, off_t *, size_t, unsigned);
ssize_t __wrap_splice(int, off_t *, int, off_t *, size_t, unsigned);
ssize_t __wrap_splice(int in, off_t *oi, int out, off_t *oo, size_t count, unsigned flags)
{
    if (pressure && moves++ != 0)
    {
        errno = EAGAIN;
        return -1;
    }
    return __real_splice(in, oi, out, oo, pressure ? min(count, (size_t) 17) : count, flags);
}
ssize_t __real_read(int, void *, size_t);
ssize_t __wrap_read(int, void *, size_t);
ssize_t __wrap_read(int fd, void *out, size_t count)
{
    ssize_t n = __real_read(fd, out, count);
    if (n > 0)
        reads += (size_t) n;
    return n;
}
#endif

typedef struct fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  lines;
    worker_t         workers[3];
    buffer_pool_t   *buffer_pools[2];
    generic_pool_t  *owner_pools[2];
    wloop_t         *loops[2];
    tunnel_chain_t  *chain;
    node_t           node;
    tunnel_t        *t, *prev, *next;
    line_t          *app, *carrier;
    twf_trace_t      trace;
    uint8_t          up[3 * 1024 * 1024], down[3 * 1024 * 1024];
    size_t           up_len, down_len, parser_reads;
    uint32_t         deliveries_up, deliveries_down, requests, ests, finishes, transport_finishes;
    uint32_t         pauses, resumes;
    unsigned         action, boundary;
    bool             udp, paused_up, paused_down, last_splice;
    sbuf_t          *last;
    uint32_t         headroom;
} fixture_t;
static fixture_t f;
static wid_t     test_wid;
static sbuf_t   *bytes(const void *data, uint32_t len, bool pipe, uint16_t padding)
{
    sbuf_t *b;
#if WW_HAVE_SPLICE
    if (pipe)
    {
        b = padding == 320 ? bufferpoolGetSpliceBuffer(f.env.pool) : twfTrackAcquired(sbufCreateSplice(padding));
        twfRequire(b != NULL && sbufSpliceInitPipe(b, 4096) == 0, "source pipe allocation failed");
        twfRequire(write(sbufSpliceMetadata(b).pipefd[1], data, len) == (ssize_t) len, "source exceeds pipe fixture");
        b->capacity = b->l_pad + len;
    }
    else
#endif
    {
        discard pipe;
        b = padding == 320 ? bufferpoolGetBestFit(f.env.pool, len, padding)
                           : twfTrackAcquired(sbufCreateWithPadding(len, padding));
        if (len != 0)
            sbufWrite(b, data, len);
    }
    sbufSetLength(b, len);
    return b;
}

static void performAction(unsigned boundary)
{
    if (f.boundary != boundary)
        return;
    unsigned action = f.action;
    f.action        = 0;
    if (action == 1 || action == 2)
    {
        f.paused_up = true;
        f.t->fnPauseD(f.t, f.carrier);
        if (action == 2)
        {
            f.paused_up = false;
            f.t->fnResumeD(f.t, f.carrier);
        }
    }
    if (action == 3 || action == 4)
    {
        f.paused_down = true;
        f.t->fnPauseU(f.t, f.app);
        if (action == 4)
        {
            f.paused_down = false;
            f.t->fnResumeU(f.t, f.app);
        }
    }
    if (action == 5)
        f.t->fnPayloadU(f.t, f.app, bytes("C", 1, false, 320));
    if (action == 6)
        f.t->fnPayloadD(f.t, f.carrier, bytes("Z", 1, false, 320));
    if (action == 7)
    {
        f.t->fnFinU(f.t, f.app);
        twfRequire(lineIsAlive(f.app), "TrojanClient destroyed a borrowed line");
        lineDestroy(f.app);
    }
    if (action == 8)
        f.t->fnFinD(f.t, f.carrier);
    if (action == 9)
        f.t->fnEstD(f.t, f.carrier);
    if (action == 10)
        f.t->fnPayloadD(f.t, f.carrier, bytes("\1\177\0\0\1\1\xbb\0\1\r\nC", 12, false, 320));
}
static void ownerFinish(tunnel_t *t, line_t *l)
{
    discard t;
    ++f.finishes;
    twfRequire(l == f.app, "Finish reached owner on carrier line");
    lineDestroy(l);
}
static void nextFinish(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == f.carrier, "Finish sent on wrong transport");
    ++f.transport_finishes;
}
static void nextInit(tunnel_t *t, line_t *l)
{
    discard t;
    f.carrier = l;
    if (l != f.app)
        lineRef(l);
    twfRequire(lineGetDestinationAddressContext(l)->proto_tcp, "carrier is not TCP");
    performAction(1);
}
static void established(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == f.app, "Est used carrier");
    ++f.ests;
    performAction(3);
}
static void receive(tunnel_t *t, line_t *l, sbuf_t *b)
{
    bool up      = t == f.next;
    bool request = up && f.requests == 0;

    twfRequire(l == (up ? f.carrier : f.app), "Payload used wrong line");
    uint32_t n    = sbufGetLength(b);
    f.last        = b;
    f.last_splice = sbufIsSplice(b);
    f.headroom    = sbufGetLeftCapacity(b);
    f.parser_reads += reads;
    reads            = 0;
    uint8_t *capture = up ? f.up : f.down;
    size_t  *length  = up ? &f.up_len : &f.down_len;
    twfRequire(*length + n <= sizeof(f.up), "fixture capture overflow");
    sbufReadRangeToMemory(b, capture + *length, n);
    reads = 0; /* Exclude the sink's materialization. */
    *length += n;
    lineReuseBuffer(l, b);
    if (request)
    {
        ++f.requests;
        performAction(2);
    }
    else
    {
        if (up)
            ++f.deliveries_up;
        else
            ++f.deliveries_down;
        performAction(up ? 4 : 5);
    }
}
static void paused(tunnel_t *t, line_t *l)
{
    twfRequire(l == (t == f.prev ? f.app : f.carrier), "Pause used wrong line");
    ++f.pauses;
    performAction(6);
}
static void resumed(tunnel_t *t, line_t *l)
{
    twfRequire(l == (t == f.prev ? f.app : f.carrier), "Resume used wrong line");
    ++f.resumes;
    performAction(7);
}
static void begin(bool udp, const char *target, uint32_t pool_size, unsigned init_action, bool context)
{
    memoryZero(&f, sizeof(f));
    fail_pipe = pressure = fail_queue = reject_growth = false;
    reads = moves = pipe_refusals = growth_refusals = 0;
    f.udp                                           = udp;
    twfWorkerEnvSetupWithBufferSizes(&f.env, pool_size, 512, 320, 8192, pool_size);
    if (test_wid != 0)
    {
        GSTATE.workers_count         = 3;
        f.workers[0]                 = f.env.worker;
        f.workers[1]                 = f.env.worker;
        f.workers[1].wid             = test_wid;
        f.buffer_pools[test_wid]     = f.env.pool;
        GSTATE.workers               = f.workers;
        GSTATE.shortcut_buffer_pools = f.buffer_pools;
        f.loops[test_wid]            = f.env.loop;
        f.env.loop->wid              = test_wid;
        GSTATE.shortcut_loops        = f.loops;
        testWorkerBindWID(test_wid);
    }
    f.node = nodeTrojanClientGet();
    twfRequire(f.node.flags == kNodeFlagSupportsSplice && f.node.required_padding_left == 263 &&
                   f.node.layer_group == kNodeLayer4 && f.node.layer_group_next_node == kNodeLayer4 &&
                   f.node.layer_group_prev_node == kNodeLayer4,
               "client capability or layer metadata changed");
    f.node.node_settings_json = cJSON_CreateObject();
    cJSON_AddStringToObject(f.node.node_settings_json, "password", "test");
    cJSON_AddStringToObject(f.node.node_settings_json, "target-address", target);
    cJSON_AddNumberToObject(f.node.node_settings_json, "port", 443);
    cJSON_AddStringToObject(f.node.node_settings_json,
                            "protocol",
                            context ? "dest_context->protocol"
                            : udp   ? "udp"
                                    : "tcp");
    f.t = trojanclientTunnelCreate(&f.node);
    twfRequire(f.t != NULL, "client construction failed");
    twfRequire(((trojanclient_tstate_t *) tunnelGetState(f.t))->first_payload_timeout_ms == 400,
               "default timeout changed");
    ((trojanclient_tstate_t *) tunnelGetState(f.t))->first_payload_timeout_ms = 0;
    f.prev                                                                    = twfCreatePrevTunnel(&f.trace);
    f.next                                                                    = twfCreateNextTunnel(&f.trace);
    tunnelBind(f.prev, f.t);
    tunnelBind(f.t, f.next);
    twfLinePoolSetup(&f.lines, f.t->lstate_size, 8);
    f.chain                       = memoryAllocateZero(sizeof(tunnel_chain_t) + 2 * sizeof(void *));
    f.chain->line_pools[0]        = f.lines.pools[0];
    f.chain->supports_splice      = WW_HAVE_SPLICE;
    f.t->chain                    = f.chain;
    f.owner_pools[0]              = f.lines.pools[0];
    f.owner_pools[test_wid]       = f.lines.pools[0];
    f.chain->line_pools[test_wid] = f.lines.pools[0];
    f.app                         = lineCreate(f.owner_pools, test_wid);
    lineRef(f.app);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(f.app), udp ? IP_PROTO_UDP : IP_PROTO_TCP);
    f.prev->fnFinD     = ownerFinish;
    f.next->fnFinU     = nextFinish;
    f.next->fnInitU    = nextInit;
    f.prev->fnEstD     = established;
    f.prev->fnPayloadD = f.next->fnPayloadU = receive;
    f.prev->fnPauseD = f.next->fnPauseU = paused;
    f.prev->fnResumeD = f.next->fnResumeU = resumed;
    f.boundary                            = 1;
    f.action                              = init_action;
    f.t->fnInitU(f.t, f.app);
    if (udp && lineIsAlive(f.app))
        twfRequire(lineGetDestinationAddressContext(f.app)->proto_udp, "application context changed to TCP");
}
static void end(void)
{
    if (lineIsAlive(f.app))
    {
        f.t->fnFinU(f.t, f.app);
        twfRequire(lineIsAlive(f.app), "client destroyed borrowed app");
        lineDestroy(f.app);
    }
    twfRequireLineStateZeroed(f.app, f.t, "application state leaked");
    if (f.carrier != f.app)
    {
        twfRequire(! lineIsAlive(f.carrier), "carrier survived teardown");
        twfRequireLineStateZeroed(f.carrier, f.t, "carrier state leaked");
        lineUnref(f.carrier);
    }
    lineUnref(f.app);
    twfLinePoolTeardown(&f.lines);
    f.t->onDestroy(f.t, wwLifecycleStartupRollback());
    tunnelDestroy(f.prev);
    tunnelDestroy(f.next);
    memoryFree(f.chain);
    cJSON_Delete(f.node.node_settings_json);
    memoryFree(f.node.type);
    if (test_wid != 0)
    {
        GSTATE.workers_count         = 2;
        GSTATE.workers               = &f.env.worker;
        GSTATE.shortcut_buffer_pools = f.env.pool_shortcut;
        GSTATE.shortcut_loops        = f.env.loop_shortcut;
        f.env.loop->wid              = 0;
        testWorkerBindWID(0);
    }
    twfWorkerEnvTeardown(&f.env);
}
static void establish(void)
{
    f.t->fnEstD(f.t, f.carrier);
    if (lineIsAlive(f.app))
        f.t->fnEstD(f.t, f.carrier);
}
static uint32_t frame(uint8_t *out, unsigned form, const void *body, uint32_t n)
{
    uint32_t h;
    memoryZero(out, 263);
    if (form == 0)
    {
        out[0] = 1;
        out[1] = 127;
        out[4] = 1;
        h      = 11;
    }
    else if (form == 1)
    {
        out[0]  = 4;
        out[16] = 1;
        h       = 23;
    }
    else
    {
        out[0] = 3;
        out[1] = form == 2 ? 1 : 255;
        memset(out + 2, 'a', out[1]);
        h = 8 + out[1];
    }
    out[h - 6] = 1;
    out[h - 5] = 187;
    out[h - 4] = (uint8_t) (n >> 8);
    out[h - 3] = (uint8_t) n;
    out[h - 2] = '\r';
    out[h - 1] = '\n';
    if (n != 0 && body != NULL)
        memoryCopy(out + h, body, n);
    return h + n;
}
static void testTcp(bool pipe)
{
    twfSetCase(pipe ? "TCP private pipes and establishment FIFO" : "TCP ordinary establishment FIFO");
    begin(false, "127.0.0.1", 65536, 0, true);
    f.t->fnPayloadU(f.t, f.app, bytes("A", 1, pipe, 320));
    f.t->fnPayloadU(f.t, f.app, bytes("B", 1, pipe, 320));
    f.t->fnPayloadD(f.t, f.carrier, bytes("X", 1, pipe, 320));
    f.boundary = 3;
    f.action   = 5;
    establish();
    twfRequire(f.requests == 1 && f.ests == 1, "duplicate request/Est");
    twfRequire(f.up_len == 71 && memcmp(f.up + 68, "ABC", 3) == 0, "reentrant Est overtook FIFO");
    twfRequire(f.down_len == 1 && f.down[0] == 'X', "server-first bytes lost");
    twfRequire(f.parser_reads == (pipe && WW_HAVE_SPLICE ? 1U : 0U), "first body not materialized exactly once");
    f.parser_reads = 0;
    for (unsigned up = 0; up < 2; ++up)
    {
        sbuf_t *b = bytes("direct", 6, pipe, 320);
        if (up)
            f.t->fnPayloadU(f.t, f.app, b);
        else
            f.t->fnPayloadD(f.t, f.app, b);
        twfRequire(f.last == b && f.last_splice == (pipe && WW_HAVE_SPLICE),
                   "opaque forwarding replaced representation");
    }
    twfRequire(f.parser_reads == 0, "TCP forwarding read the body");
    end();
}
static void testRequestAndPause(void)
{
    char domain[256];
    memset(domain, 'a', 255);
    domain[255] = 0;
    twfSetCase("maximum first combined request completes through Pause");
    begin(false, domain, 128, 1, false);
    f.t->fnPayloadU(f.t, f.app, bytes("A", 1, false, 320));
    establish();
    twfRequire(f.requests == 1 && f.ests == 1 && f.up_len == 321, "combined request waited for Pause/Est");
    twfRequire(f.up[58] == 1 && f.up[59] == 3 && f.up[60] == 255 && f.up[318] == '\r' && f.up[319] == '\n',
               "request encoding changed");
    f.paused_up = false;
    f.t->fnResumeD(f.t, f.carrier);
    twfRequire(f.requests == 1 && f.up_len == 321, "Resume duplicated request");
    end();
}
static void testUdp(unsigned form, bool pipe)
{
    twfSetCase("UDP wire formats, sizes, padding and exact header reads");
    char domain[256];
    memset(domain, 'a', 255);
    domain[255]        = 0;
    const char *target = form == 0 ? "127.0.0.1" : form == 1 ? "::1" : form == 2 ? "a" : domain;
    uint8_t     payload[8193], wire[9000];
    for (unsigned i = 0; i < sizeof(payload); ++i)
        payload[i] = (uint8_t) (i * 17 + 3);
    const uint32_t sizes[] = {0, 1, 8192, 8193};
    for (unsigned i = 0; i < 4; ++i)
    {
        for (unsigned pad = 0; pad < 2; ++pad)
        {
            begin(true, target, 512, 0, true);
            establish();
            twfRequire(f.up_len == 68 && f.up[58] == 3 && memcmp(f.up + 59, "\1\0\0\0\0\0\0", 7) == 0,
                       "UDP request changed");
            uint32_t n = sizes[i];
            /* Larger bodies are ordinary: receive tests assemble large bodies
             * from small pipes, without depending on privileged pipe growth. */
            f.t->fnPayloadU(f.t, f.app, bytes(payload, n, pipe && n <= 4096, pad ? 320 : 0));
            if (n > 8192)
                twfRequire(f.deliveries_up == 0 && lineIsAlive(f.app), "oversized local datagram killed association");
            else
            {
                uint32_t len = frame(wire, form, payload, n);
                twfRequire(f.deliveries_up == 1 && f.up_len == 68 + len && memcmp(f.up + 68, wire, len) == 0,
                           "UDP send changed datagram");
                f.t->fnPayloadD(f.t, f.carrier, bytes(wire, len, pipe && len <= 4096, 320));
                twfRequire(f.deliveries_down == 1 && f.down_len == n && memcmp(f.down, payload, n) == 0,
                           "UDP receive changed datagram");
                twfRequire(f.headroom >= 320, "onward padding lost");
                twfRequire(f.parser_reads == (pipe && WW_HAVE_SPLICE && len <= 4096 ? len - n : 0),
                           "parser read unnecessary bytes");
            }
            end();
        }
    }
}
static void testSplits(unsigned form)
{
    twfSetCase("all UDP header splits, mixed bodies and partial next header");
    uint8_t  wire[1000];
    uint32_t first  = frame(wire, form, "ABC", 3);
    uint32_t second = frame(wire + first, 0, "DE", 2);
    uint32_t h      = first - 3;
    for (uint32_t split = 1; split < first; ++split)
    {
        begin(true, "127.0.0.1", 65536, 0, false);
        establish();
        f.t->fnPayloadD(f.t, f.carrier, bytes(wire, split, true, 320));
        twfRequire(f.deliveries_down == 0, "partial frame delivered");
        f.t->fnPayloadD(f.t, f.carrier, bytes(wire + split, first + second - split - 1, true, 320));
        twfRequire(f.deliveries_down == 1, "frame boundary ignored");
        bool first_pipe = f.last_splice;
        f.t->fnPayloadD(f.t, f.carrier, bytes(wire + first + second - 1, 1, false, 320));
        twfRequire(f.deliveries_down == 2 && memcmp(f.down, "ABCDE", 5) == 0, "split/coalesced payload changed");
        /* One-slot destination pipes may legitimately materialize the body.
         * Successful private-pipe extraction must read only headers. */
        size_t expected_reads = WW_HAVE_SPLICE ? h + 11 + (first_pipe ? 0 : 3) + (f.last_splice ? 0 : 1) : 0;
        twfRequire(f.parser_reads == expected_reads, "header reads crossed a preserved private body");
        end();
    }
}
static void testUdpPause(void)
{
    twfSetCase("admitted UDP batches complete through Pause with no decoded backlog");
    uint8_t wire[20000];
    for (unsigned close = 0; close < 2; ++close)
    {
        begin(true, "127.0.0.1", 128, 0, false);
        establish();

        unsigned length = 0;
        for (unsigned i = 0; i < 1500; ++i)
            length += frame(wire + length, 0, "x", 0);
        f.boundary = 5;
        f.action   = close ? 8 : 3;
        f.t->fnPayloadD(f.t, f.carrier, bytes(wire, length, false, 320));
        twfRequire(f.deliveries_down == (close ? 1U : 1500U), "batch paused early or continued after Finish");
        if (! close)
        {
            trojanclient_lstate_t *ls = lineGetState(f.carrier, f.t);
            twfRequire(ls->receive_bytes == 0 && bufferqueueGetBufCount(&ls->pending_down) == 0,
                       "ready datagrams retained for Resume");
            f.paused_down = false;
            f.t->fnResumeU(f.t, f.app);
            twfRequire(f.deliveries_down == 1500, "Resume replayed batch");
        }
        end();
    }
    begin(true, "127.0.0.1", 128, 0, false);
    establish();

    unsigned length = 0;
    length += frame(wire + length, 0, "A", 1);
    length += frame(wire + length, 0, "B", 1);
    f.boundary = 5;
    f.action   = 10;
    f.t->fnPayloadD(f.t, f.carrier, bytes(wire, length, false, 320));
    twfRequire(f.down_len == 3 && memcmp(f.down, "ABC", 3) == 0, "nested admitted batch overtook older input");
    end();
}
static void testMalformed(void)
{
    twfSetCase("malformed UDP is association-local");
    uint8_t wire[9000];
    for (unsigned fault = 0; fault < 5; ++fault)
    {
        begin(true, "127.0.0.1", 65536, 0, false);
        establish();
        uint32_t n = frame(wire, 0, "A", 1);
        if (fault == 0)
            wire[0] = 7;
        if (fault == 1)
        {
            wire[0] = 3;
            wire[1] = 0;
        }
        if (fault == 2)
        {
            wire[5] = 0;
            wire[6] = 0;
        }
        if (fault == 3)
            wire[10] = 'x';
        if (fault == 4)
        {
            wire[7] = 32;
            wire[8] = 1;
        }
        f.t->fnPayloadD(f.t, f.carrier, bytes(wire, n, true, 320));
        twfRequire(! lineIsAlive(f.app) && ! lineIsAlive(f.carrier) && f.deliveries_down == 0,
                   "malformed frame survived");
        end();
    }
}
static void testLimits(uint32_t pool_size)
{
    twfSetCase("parser retained-byte equality and one-over refusal");
    for (unsigned udp = 1; udp < 2; ++udp)
    {
        begin(udp, "127.0.0.1", pool_size, 0, false);
        trojanclient_lstate_t *ls    = lineGetState(f.carrier, f.t);
        size_t                 limit = kTrojanClientMaxUdpBufferedBytes;
        uint8_t               *data  = memoryAllocateZero(limit);
        /* Model nested input while an outer parser owns the cursor. No callbacks
         * may run until that admission returns to its real outer dispatch. */
        ls->receiving = true;
        f.t->fnPayloadD(f.t, f.carrier, bytes(data, (uint32_t) limit, false, 320));
        twfRequire(lineIsAlive(f.app) && ls->receive_bytes == limit, "exact retained limit refused");
        f.t->fnPayloadD(f.t, f.carrier, bytes("x", 1, false, 320));
        twfRequire(! lineIsAlive(f.app), "retained input overflow survived");
        memoryFree(data);
        end();
    }
}
static void testFailuresAndClose(void)
{
    twfSetCase("parser admission refusal and Finish at real callback boundaries");
    for (unsigned udp = 0; udp < 2; ++udp)
    {
        if (udp || false)
        {
            begin(udp, "127.0.0.1", 128, 0, false);
            fail_queue = true;
            f.t->fnPayloadD(f.t, f.carrier, bytes("x", 1, true, 320));
            twfRequire(! lineIsAlive(f.app), "parser queue refusal left flow alive");
            end();
        }
        for (unsigned action = 7; action <= 8; ++action)
            for (unsigned boundary = 1; boundary <= 7; ++boundary)
            {
                begin(udp, "127.0.0.1", 128, boundary == 1 ? action : 0, false);
                if (boundary != 1)
                {
                    if (boundary >= 4)
                        establish();
                    if (boundary == 5 && ! true)
                        f.t->fnPayloadD(f.t, f.carrier, bytes("\0\0", 2, false, 320));
                    f.boundary = boundary;
                    f.action   = action;
                    if (boundary == 2 || boundary == 3)
                        establish();
                    if (boundary == 4)
                        f.t->fnPayloadU(f.t, f.app, bytes("A", 1, true, 320));
                    if (boundary == 5)
                        f.t->fnPayloadD(
                            f.t, f.carrier, bytes(udp ? "\1\177\0\0\1\1\xbb\0\1\r\nC" : "A", udp ? 12 : 1, true, 320));
                    if (boundary >= 6)
                    {
                        f.t->fnPauseD(f.t, f.carrier);
                        if (boundary == 7)
                            f.t->fnResumeD(f.t, f.carrier);
                    }
                }
                twfRequire(! lineIsAlive(f.app), "Finish callback did not close app");
                twfRequire(f.transport_finishes == (action == 7 ? 1U : 0U), "Finish reflected toward sender");
                end();
            }
    }
}
static void testFallback(void)
{
    twfSetCase("split pipe bodies and complete pressure fallback");
    uint8_t payload[8192], wire[9000];
    memset(payload, 'p', sizeof(payload));
    uint32_t n = frame(wire, 0, payload, sizeof(payload));
    for (unsigned fault = 0; fault < 4; ++fault)
    {
        begin(true, "127.0.0.1", 128, 0, false);
        establish();
        for (unsigned offset = 0; offset < n;)
        {
            unsigned size = min(2048U, n - offset);
            sbuf_t  *part = bytes(wire + offset, size, true, 320);
            if (offset + size == n)
            {
                fail_pipe     = fault == 1;
                pressure      = fault == 2;
                reject_growth = fault == 3;
            }
            f.t->fnPayloadD(f.t, f.carrier, part);
            offset += size;
        }
        twfRequire(f.deliveries_down == 1 && f.down_len == 8192 && memcmp(f.down, payload, 8192) == 0,
                   "fallback lost partial pipe progress");
        twfRequire(f.headroom >= 320, "fallback lost onward padding");
#if WW_HAVE_SPLICE
        if (fault == 1)
            twfRequire(pipe_refusals != 0 && ! f.last_splice, "pipe refusal did not select ordinary fallback");
        if (fault == 2)
            twfRequire(moves >= 2 && ! f.last_splice, "partial transfer pressure did not select complete fallback");
        if (fault == 3)
            twfRequire(growth_refusals != 0 && ! f.last_splice,
                       "small destination pipe did not exercise growth fallback");
#endif
        end();
    }
}

static void testPrefixesAndFragments(void)
{
    twfSetCase("resident prefixes, mixed assembly, exact padding and unrestricted fragments");
    begin(true, "127.0.0.1", 128, 0, false);
    establish();
    sbuf_t *b = bytes("body", 4, true, 320);
    sbufShiftLeft(b, 3);
    sbufWrite(b, "pre", 3);
    f.t->fnPayloadU(f.t, f.app, b);
    twfRequire(f.up_len == 86 && memcmp(f.up + 79, "prebody", 7) == 0, "resident prefix was overwritten");
    twfRequire(f.parser_reads == 0, "padded UDP send read body");
    uint8_t  wire[2048];
    uint32_t n = frame(wire, 0, "prebody", 7);
    b          = bytes(wire + 11, 7, true, 320);
    sbufShiftLeft(b, 11);
    sbufWrite(b, wire, 11);
    f.t->fnPayloadD(f.t, f.carrier, b);
    twfRequire((! WW_HAVE_SPLICE || f.last == b) && f.down_len == 7 && memcmp(f.down, "prebody", 7) == 0,
               "whole private body not transferred");
    twfRequire(f.parser_reads == 0, "resident header materialized pipe body");
    /* One ordinary body byte, two pipe bytes, one ordinary byte: assembly must
     * select a pipe before consuming the first source. */
    n = frame(wire, 0, "ABCD", 4);
    f.t->fnPayloadD(f.t, f.carrier, bytes(wire, 12, false, 320));
    f.t->fnPayloadD(f.t, f.carrier, bytes(wire + 12, 2, true, 320));
    f.t->fnPayloadD(f.t, f.carrier, bytes(wire + 14, 1, false, 320));
    twfRequire(memcmp(f.down + 7, "ABCD", 4) == 0, "mixed body bytes changed");
    twfRequire(f.last_splice ? f.parser_reads == 0 : f.parser_reads <= 4,
               "mixed extraction read beyond its body or materialized a preserved pipe");
    /* The queue's 1,024-output-entry bound is not an input fragment bound. */
    memset(wire + 11, 'x', 1500);
    n = frame(wire, 0, NULL, 1500);
    memset(wire + 11, 'x', 1500);
    f.paused_down = true;
    f.t->fnPauseU(f.t, f.app);
    for (unsigned i = 0; i < n; ++i)
        f.t->fnPayloadD(f.t, f.carrier, bytes(wire + i, 1, false, 320));
    twfRequire(lineIsAlive(f.app) && f.deliveries_down == 3, "valid fragment count rejected");
    f.paused_down = false;
    f.t->fnResumeU(f.t, f.app);
    twfRequire(f.deliveries_down == 3 && f.down_len == 1511, "fragmented datagram boundary changed");
    end();

    begin(true, "127.0.0.1", 128, 0, false);
    /* Receive output needs more headroom than this source or the splice pool.
     * Shared helpers must return a sufficiently padded ordinary replacement. */
    bufferpoolUpdateAllocationPaddings(f.env.pool, 352, 352, 352, 32);
    establish();
    n = frame(wire, 0, "padded", 6);
    b = bytes(wire, n, true, 32);
    f.t->fnPayloadD(f.t, f.carrier, b);
    twfRequire(f.headroom >= 352 && memcmp(f.down, "padded", 6) == 0, "receive replacement lost padding");
    b = bytes("send", 4, true, 0);
    f.t->fnPayloadU(f.t, f.app, b);
    twfRequire(f.headroom >= 352 - 11 && memcmp(f.up + 79, "send", 4) == 0, "send replacement lost padding");
    end();
}

static void testReentrancy(void)
{
    twfSetCase("request and Est reentry publish before callbacks");
    for (unsigned udp = 0; udp < 2; ++udp)
    {
        begin(udp, "127.0.0.1", 128, 0, false);
        f.boundary = 2;
        f.action   = 9;
        f.t->fnPayloadU(f.t, f.app, bytes("A", 1, true, 320));
        establish();
        twfRequire(f.ests == 1 && f.requests == 1, "nested Est duplicated request or signal");
        end();
        begin(udp, "127.0.0.1", 128, 0, false);
        f.boundary = 3;
        f.action   = 5;
        establish();
        twfRequire(f.ests == 1 && f.requests == 1 && f.up_len == 68 + (udp ? 12 : 1),
                   "Est input was split from request");
        end();
        begin(udp, "127.0.0.1", 128, 0, false);
        f.boundary = 2;
        f.action   = 5;
        f.t->fnPayloadU(f.t, f.app, bytes("A", 1, true, 320));
        twfRequire(f.requests == 1 && f.up[79 * udp + 68 * ! udp] == 'A' && f.up[f.up_len - 1] == 'C',
                   "nested payload overtook initial output");
        end();
    }
}

static void testSetupAndCallbackBudget(void)
{
    twfSetCase("failed setup and admission during Est");
    begin(false, "127.0.0.1", 128, 0, false);
    f.t->fnFinU(f.t, f.app);
    lineDestroy(f.app);
    lineUnref(f.app);
    f.app = f.carrier = twfLinePoolCreateLine(&f.lines);
    lineRef(f.app);
    trojanclient_tstate_t *ts = tunnelGetState(f.t);
    ts->target_port_source    = kDvsFirstOption;
    f.t->fnInitU(f.t, f.app);
    twfRequire(! lineIsAlive(f.app) && f.finishes == 1 && f.transport_finishes == 1,
               "failed target setup finished an uninitialized next branch");
    end();
}

static void testFirstPayload(void)
{
    twfSetCase("ordinary first output materializes prefix and pipe before Est");
    for (unsigned udp = 0; udp < 2; ++udp)
        for (unsigned representation = 0; representation < 3; ++representation)
        {
            begin(udp, "127.0.0.1", 128, 1, true);
            twfRequire(f.requests == 0 && f.up_len == 0, "Init emitted request");
            sbuf_t *body = bytes("body", 4, representation != 0, 320);
            if (representation == 2)
            {
                sbufShiftLeft(body, 3);
                sbufWrite(body, "pre", 3);
            }
            unsigned length = representation == 2 ? 7 : 4;
            f.t->fnPayloadU(f.t, f.app, body);
            twfRequire(f.requests == 1 && f.deliveries_up == 0 && ! f.last_splice && f.headroom >= 320,
                       "initial output split, splice-backed or missing padding");
            twfRequire(f.up_len == 68 + (udp ? 11 : 0) + length &&
                           memcmp(f.up + f.up_len - length, representation == 2 ? "prebody" : "body", length) == 0,
                       "combined first payload lost bytes");
            establish();
            twfRequire(f.ests == 1 && wloopNTimers(f.env.loop) == 0, "pre-Est send created timer or duplicate signal");
            end();
        }
    begin(false, "127.0.0.1", 128, 0, false);
    f.t->fnPayloadU(f.t, f.app, bytes("", 0, false, 320));
    twfRequire(f.requests == 0, "empty TCP triggered request");
    end();
    begin(true, "127.0.0.1", 128, 0, false);
    f.t->fnPayloadU(f.t, f.app, bytes("", 0, false, 320));
    twfRequire(f.requests == 1, "empty UDP policy changed");
    end();
}

static void testInitialAllocationRefusal(void)
{
    twfSetCase("unrepresentable first-output refusal settles source and waiting timer");
    for (unsigned udp = 0; udp < 2; ++udp)
    {
        begin(udp, "127.0.0.1", 128, 0, false);
        ((trojanclient_tstate_t *) tunnelGetState(f.t))->first_payload_timeout_ms = 400;
        establish();
        sbuf_t *body            = bytes("owned", 5, true, 320);
        fail_initial_allocation = true;
        f.t->fnPayloadU(f.t, f.app, body);
        twfRequire(! lineIsAlive(f.app) && f.requests == 0 && wloopNTimers(f.env.loop) == 0,
                   "failed initial allocation leaked source, timer or association");
        end();
    }
}

static void testTimeoutConfiguration(void)
{
    twfSetCase("real constructor timeout range and invalid JSON values");
    const char *values[] = {"0", "17", "4294967295", "-1", "0.5", "null", "true", "\"17\"", "4294967296"};
    for (unsigned i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
    {
        begin(false, "127.0.0.1", 128, 0, false);
        cJSON_AddItemToObject(f.node.node_settings_json, "first-payload-timeout-ms", cJSON_Parse(values[i]));
        tunnel_t *other = trojanclientTunnelCreate(&f.node);
        twfRequire((other != NULL) == (i < 3), "constructor timeout acceptance changed");
        if (other != NULL)
        {
            uint32_t expected = i == 0 ? 0U : i == 1 ? 17U : UINT32_MAX;
            twfRequire(((trojanclient_tstate_t *) tunnelGetState(other))->first_payload_timeout_ms == expected,
                       "constructor truncated timeout");
            other->onDestroy(other, wwLifecycleStartupRollback());
        }
        end();
    }
}

static void testTimers(void)
{
    twfSetCase("deadline cancellation, paused due work, early dispatch and quiescence");
    begin(false, "127.0.0.1", 128, 1, false);
    establish();
    twfRequire(f.ests == 1 && f.requests == 0 && wloopNTimers(f.env.loop) == 0,
               "zero timeout emitted idle header through Pause or withheld Est");
    f.t->fnResumeD(f.t, f.carrier);
    twfRequire(f.requests == 1, "zero timeout due header stranded on Resume");
    end();
    for (unsigned udp = 0; udp < 2; ++udp)
        for (unsigned mode = 0; mode < 8; ++mode)
        {
            begin(udp, "127.0.0.1", 128, 0, false);
            ((trojanclient_tstate_t *) tunnelGetState(f.t))->first_payload_timeout_ms = 400;
            establish();
            trojanclient_lstate_t *ls = lineGetState(f.carrier, f.t);
            twfRequire(f.ests == 1 && f.requests == 0 && ls->first_payload_timer != NULL,
                       "idle deadline missing or header sent early");
            uint64_t deadline = ls->first_payload_deadline_us;
            establish();
            twfRequire(ls->first_payload_deadline_us == deadline && wloopNTimers(f.env.loop) == 1,
                       "duplicate Est reset deadline");
            if (mode == 0)
            {
                f.t->fnPayloadU(f.t, f.app, bytes("A", 1, true, 320));
                twfRequire(ls->first_payload_timer == NULL && wloopNTimers(f.env.loop) == 0 &&
                               f.up_len == 68 + (udp ? 11 + 1 : 1),
                           "data did not cancel timer");
            }
            else if (mode == 1)
            {
                wtimerTestMakePendingOneShot(ls->first_payload_timer);
                discard wloopProcessEvents(f.env.loop, 0);
                twfRequire(f.requests == 0 && ls->first_payload_timer != NULL && wloopNTimers(f.env.loop) == 1,
                           "early rounded expiry violated absolute deadline");
            }
            else if (mode == 2)
            {
                wloopCloseNormalAdmission(f.env.loop);
                wloopQuiesceNormalWork(f.env.loop);
                twfRequire(ls->first_payload_timer->quiesced && f.requests == 0,
                           "quiescence emitted header or reclaimed owner's timer handle");
            }
            else if (mode == 3)
            {
                wtimerTestMakePendingOneShot(ls->first_payload_timer);
                f.t->fnFinD(f.t, f.carrier);
                discard wloopProcessEvents(f.env.loop, 0);
                twfRequire(! lineIsAlive(f.app) && f.requests == 0, "canceled pending timer emitted header");
            }
            else
            {
                if (mode != 4)
                    f.t->fnPauseD(f.t, f.carrier);
                ls->first_payload_deadline_us = getHRTimeUs() - 1;
                wtimerTestMakePendingOneShot(ls->first_payload_timer);
                if (mode == 4)
                {
                    f.boundary = 2;
                    f.action   = 8;
                }
                discard wloopProcessEvents(f.env.loop, 0);
                if (mode == 4)
                    twfRequire(! lineIsAlive(f.app) && f.requests == 1, "timer callback Finish leaked line");
                else
                {
                    twfRequire(f.requests == 0 && ls->first_payload_due && ls->first_payload_timer == NULL,
                               "timer sent through Pause or retained executing one-shot");
                    if (mode == 5)
                        f.t->fnResumeD(f.t, f.carrier);
                    else if (mode == 6)
                        f.t->fnPayloadU(f.t, f.app, bytes("A", 1, true, 320));
                    else
                    {
                        f.boundary = 7;
                        f.action   = 5;
                        f.t->fnResumeD(f.t, f.carrier);
                    }
                    twfRequire(f.requests == 1 && ! ls->first_payload_due && wloopNTimers(f.env.loop) == 0 &&
                                   f.up_len == 68 + (mode == 5 ? 0
                                                     : udp     ? 11 + 1
                                                               : 1),
                               "due header duplicated, failed to combine, or failed Resume");
                    f.t->fnResumeD(f.t, f.carrier);
                    twfRequire(f.requests == 1, "duplicate Resume repeated request");
                }
            }
            end();
        }
    begin(false, "127.0.0.1", 128, 0, false);
    ((trojanclient_tstate_t *) tunnelGetState(f.t))->first_payload_timeout_ms = 400;
    wloopCloseNormalAdmission(f.env.loop);
    establish();
    twfRequire(! lineIsAlive(f.app) && f.requests == 0, "timer admission refusal stranded line");
    end();
    begin(false, "127.0.0.1", 128, 0, false);
    ((trojanclient_tstate_t *) tunnelGetState(f.t))->first_payload_timeout_ms = 1;
    establish();
    uint64_t stop = getHRTimeUs() + 1000000;
    while (f.requests == 0 && getHRTimeUs() < stop)
        discard wloopProcessEvents(f.env.loop, 5);
    twfRequire(f.requests == 1 && f.up_len == 68, "real-loop timer did not expire");
    end();
}

static void testNestedClients(void)
{
    twfSetCase("nested clients combine a 1 MiB body before Est");
    char domain[256];
    memset(domain, 'a', 255);
    domain[255] = 0;
    begin(false, domain, 128, 0, false);
    f.t->fnFinU(f.t, f.app);
    lineDestroy(f.app);
    lineUnref(f.app);
    twfLinePoolTeardown(&f.lines);
    tunnel_t *inner = trojanclientTunnelCreate(&f.node);
    twfRequire(inner != NULL, "nested client construction failed");
    inner->lstate_offset = f.t->lstate_size;
    inner->chain         = f.chain;
    tunnelBind(f.t, inner);
    tunnelBind(inner, f.next);
    twfLinePoolSetup(&f.lines, f.t->lstate_size + inner->lstate_size, 8);
    f.chain->line_pools[0] = f.lines.pools[0];
    f.app = f.carrier = twfLinePoolCreateLine(&f.lines);
    lineRef(f.app);
    f.t->fnInitU(f.t, f.app);
    uint32_t length = 1024 * 1024;
    uint8_t *data   = memoryAllocate(length);
    memset(data, 'x', length);
    f.t->fnPayloadU(f.t, f.app, bytes(data, length, false, 320));
    twfRequire(f.requests == 1 && f.deliveries_up == 0 && ! f.last_splice && f.up_len == length + 640 &&
                   memcmp(f.up + 640, data, length) == 0,
               "nested first requests split or truncated body");
    memoryFree(data);
    sbuf_t *later = bytes("later", 5, true, 320);
    f.t->fnPayloadU(f.t, f.app, later);
    twfRequire(f.last == later && f.last_splice == (bool) WW_HAVE_SPLICE, "nested later TCP lost splice identity");
    end();
    inner->onDestroy(inner, wwLifecycleStartupRollback());
}

static void testTimerWorker(void)
{
    twfSetCase("timer uses exact nonzero carrier worker");
    test_wid = 1;
    begin(true, "127.0.0.1", 128, 0, false);
    ((trojanclient_tstate_t *) tunnelGetState(f.t))->first_payload_timeout_ms = 400;
    establish();
    trojanclient_lstate_t *ls = lineGetState(f.carrier, f.t);
    twfRequire(lineGetWID(f.carrier) == 1 && ls->first_payload_timer != NULL &&
                   ls->first_payload_timer->loop == f.env.loop && ls->first_payload_timer->loop->wid == 1,
               "timer used foreign worker loop");
    end();
    test_wid = 0;
}

int main(void)
{
    twfRequire(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");
    testFirstPayload();
    testInitialAllocationRefusal();
    testTimeoutConfiguration();
    testTimers();
    testTimerWorker();
    testNestedClients();
    testTcp(false);
    testTcp(true);
    testRequestAndPause();
    for (unsigned form = 0; form < 4; ++form)
    {
        testUdp(form, false);
        testUdp(form, true);
        testSplits(form);
    }
    testPrefixesAndFragments();
    testReentrancy();
    testUdpPause();
    testMalformed();
    testLimits(128);
    testLimits(128 * 1024);
    testFailuresAndClose();
    testFallback();
    testSetupAndCallbackBudget();
    puts("TrojanClient framing, splice, pressure, limits and lifetime tests passed");
    return 0;
}
