#include "VlessClient/interface.h"
#include "dns_strategy.h"
#include "splice_buffer.h"
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
    generic_pool_t  *owner_pools[2];
    worker_t         workers[3];
    buffer_pool_t   *buffer_pools[2];
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
    bool             inject_extra;
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
        twfRequire(lineIsAlive(f.app), "VlessClient destroyed a borrowed line");
        lineDestroy(f.app);
    }
    if (action == 8)
        f.t->fnFinD(f.t, f.carrier);
    if (action == 9)
        f.t->fnEstD(f.t, f.carrier);
    if (action == 10)
        f.t->fnPayloadD(f.t, f.carrier, bytes("\0\1C", 3, false, 320));
    if (action == 11)
    {
        uint8_t *data = memoryAllocate(kVlessClientMaxOrderBytes);
        memset(data, 'r', kVlessClientMaxOrderBytes);
        f.t->fnPayloadD(f.t, f.carrier, bytes(data, kVlessClientMaxOrderBytes, false, 320));
        if (f.inject_extra)
            f.t->fnPayloadD(f.t, f.carrier, bytes("x", 1, false, 320));
        memoryFree(data);
    }
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
    twfRequire(lineGetWID(l) == test_wid && lineGetWID(f.app) == test_wid, "carrier changed owner worker");
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
        f.buffer_pools[1]            = f.env.pool;
        GSTATE.workers               = f.workers;
        GSTATE.shortcut_buffer_pools = f.buffer_pools;
        f.loops[test_wid]            = f.env.loop;
        f.env.loop->wid              = test_wid;
        GSTATE.shortcut_loops        = f.loops;
        testWorkerBindWID(test_wid);
    }
    f.node = nodeVlessClientGet();
    twfRequire(f.node.flags == kNodeFlagSupportsSplice && f.node.required_padding_left == 2 &&
                   f.node.layer_group == kNodeLayer4 && f.node.layer_group_next_node == kNodeLayer4 &&
                   f.node.layer_group_prev_node == kNodeLayer4,
               "client capability or layer metadata changed");
    f.node.node_settings_json = cJSON_CreateObject();
    cJSON_AddStringToObject(f.node.node_settings_json, "uuid", "5783a3e7-e373-51cd-8642-c83782b807c5");
    cJSON_AddStringToObject(f.node.node_settings_json, "target-address", target);
    cJSON_AddNumberToObject(f.node.node_settings_json, "port", 443);
    cJSON_AddStringToObject(f.node.node_settings_json,
                            "protocol",
                            context ? "dest_context->protocol"
                            : udp   ? "udp"
                                    : "tcp");
    f.t = vlessclientTunnelCreate(&f.node);
    twfRequire(f.t != NULL, "client construction failed");
    twfRequire(((vlessclient_tstate_t *) tunnelGetState(f.t))->first_payload_timeout_ms == 400,
               "default timeout changed");
    ((vlessclient_tstate_t *) tunnelGetState(f.t))->first_payload_timeout_ms = 0;
    f.prev                                                                   = twfCreatePrevTunnel(&f.trace);
    f.next                                                                   = twfCreateNextTunnel(&f.trace);
    tunnelBind(f.prev, f.t);
    tunnelBind(f.t, f.next);
    twfLinePoolSetup(&f.lines, f.t->lstate_size, 8);
    f.chain                       = memoryAllocateZero(sizeof(tunnel_chain_t) + 2 * sizeof(void *));
    f.chain->line_pools[0]        = f.lines.pools[0];
    f.owner_pools[0]              = f.lines.pools[0];
    f.chain->line_pools[test_wid] = f.lines.pools[0];
    f.owner_pools[test_wid]       = f.lines.pools[0];
    f.chain->supports_splice      = WW_HAVE_SPLICE;
    f.t->chain                    = f.chain;
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
static void testBaseline(void)
{
    for (unsigned udp = 0; udp < 2; ++udp)
    {
        twfSetCase("VLESS early Est and pre-response outbound progress");
        begin(udp, "127.0.0.1", 65536, 0, true);
        f.t->fnPayloadU(f.t, f.app, bytes("A", 1, false, 320));
        f.boundary = 3;
        f.action   = 5;
        establish();
        const uint8_t expected[] = {0,    0x57, 0x83, 0xa3, 0xe7, 0xe3, 0x73, 0x51, 0xcd, 0x86, 0x42, 0xc8, 0x37,
                                    0x82, 0xb8, 0x07, 0xc5, 0,    1,    1,    0xbb, 1,    127,  0,    0,    1};
        twfRequire(f.requests == 1 && f.ests == 1, "duplicate request/Est");
        twfRequire(memcmp(f.up, expected, 18) == 0 && f.up[18] == (udp ? 2 : 1) &&
                       memcmp(f.up + 19, expected + 19, 7) == 0,
                   "wire request changed");
        twfRequire(f.up_len == (udp ? 32 : 28), "outbound waited for response");
        twfRequire(memcmp(f.up + 26, udp ? "\0\1A\0\1C" : "AC", udp ? 6 : 2) == 0, "Est FIFO changed");
        end();
    }
}

static void response(void)
{
    f.t->fnPayloadD(f.t, f.carrier, bytes("\0\0", 2, false, 320));
}
static uint32_t frame(uint8_t *out, const void *body, uint32_t n)
{
    out[0] = (uint8_t) (n >> 8);
    out[1] = (uint8_t) n;
    if (n != 0 && body != NULL)
        memoryCopy(out + 2, body, n);
    return n + 2;
}
static void testResponse(bool pipe)
{
    twfSetCase("response splits, addons, opaque TCP and UDP transition");
    uint8_t  wire[300];
    unsigned addons[] = {0, 1, 255};
    for (unsigned udp = 0; udp < 2; ++udp)
        for (unsigned a = 0; a < 3; ++a)
        {
            unsigned header = 2 + addons[a];
            wire[0]         = 0;
            wire[1]         = (uint8_t) addons[a];
            memset(wire + 2, 0xff, addons[a]);
            unsigned total = header + (udp ? frame(wire + header, "ABC", 3) : 3);
            if (! udp)
                memcpy(wire + header, "ABC", 3);
            for (unsigned split = 0; split <= total; ++split)
            {
                begin(udp, "127.0.0.1", 128, 0, false);
                establish();
                f.t->fnPayloadD(f.t, f.carrier, bytes(wire, split, pipe, 320));
                if (split < header || (udp && split < total))
                    twfRequire(f.down_len == 0, "metadata or partial datagram leaked");
                f.t->fnPayloadD(f.t, f.carrier, bytes(wire + split, total - split, pipe, 320));
                twfRequire(f.down_len == 3 && memcmp(f.down, "ABC", 3) == 0, "response consumed body");
                twfRequire(! udp || f.deliveries_down == 1, "UDP response boundary lost");
                if (pipe && WW_HAVE_SPLICE && (! udp || f.last_splice))
                    twfRequire(f.parser_reads == header + (udp ? 2 : 0), "parser read pipe body");
                end();
            }
        }
}
static void testTcp(bool pipe)
{
    twfSetCase("opaque TCP identity, early FIFO and nested receive");
    begin(false, "127.0.0.1", 65536, 0, true);
    f.t->fnPayloadU(f.t, f.app, bytes("A", 1, pipe, 320));
    f.t->fnPayloadU(f.t, f.app, bytes("B", 1, pipe, 320));
    f.t->fnPayloadD(f.t, f.app, bytes("\0\0X", 3, false, 320));
    f.boundary = 3;
    f.action   = 5;
    establish();
    twfRequire(f.up_len == 29 && memcmp(f.up + 26, "ABC", 3) == 0 && f.down_len == 1, "early FIFO changed");
    f.parser_reads = 0;
    for (unsigned up = 0; up < 2; ++up)
    {
        sbuf_t *b = bytes("direct", 6, pipe, 320);
        if (up)
            f.t->fnPayloadU(f.t, f.app, b);
        else
            f.t->fnPayloadD(f.t, f.app, b);
        twfRequire(f.last == b && f.last_splice == (pipe && WW_HAVE_SPLICE), "opaque forwarding replaced buffer");
    }
    twfRequire(f.parser_reads == 0, "opaque TCP materialized");
    end();
}
static void testRequests(void)
{
    twfSetCase("all destination encodings, fixed/context protocols, paused early Est");
    char domain[256];
    memset(domain, 'a', 255);
    domain[255]              = 0;
    const char    *targets[] = {"127.0.0.1", "::1", "a", domain};
    const unsigned lengths[] = {26, 38, 24, 278};
    for (unsigned udp = 0; udp < 2; ++udp)
        for (unsigned context = 0; context < 2; ++context)
            for (unsigned form = 0; form < 4; ++form)
            {
                begin(udp, targets[form], 128, 1, context);
                f.t->fnPayloadU(f.t, f.app, bytes("A", 1, false, 320));
                f.boundary = 3;
                f.action   = 9;
                establish();
                twfRequire(f.ests == 1 && f.requests == 1, "combined send or early Est gated by Pause");
                f.paused_up = false;
                f.t->fnResumeD(f.t, f.carrier);
                twfRequire(f.requests == 1 && f.up_len == lengths[form] + (udp ? 3 : 1), "request size changed");
                twfRequire(f.up[18] == (udp ? 2 : 1) && f.up[19] == 1 && f.up[20] == 187, "command/port changed");
                if (form == 0)
                    twfRequire(memcmp(f.up + 21, "\1\177\0\0\1", 5) == 0, "IPv4 changed");
                else if (form == 1)
                {
                    uint8_t ip[17] = {3};
                    ip[16]         = 1;
                    twfRequire(memcmp(f.up + 21, ip, sizeof(ip)) == 0, "IPv6 changed");
                }
                else
                    twfRequire(f.up[21] == 2 && f.up[22] == strlen(targets[form]) &&
                                   memcmp(f.up + 23, targets[form], strlen(targets[form])) == 0,
                               "domain changed");
                end();
            }
}
static void testUdp(bool pipe)
{
    twfSetCase("UDP length boundaries, padding and invalid local drops");
    uint8_t payload[65536], wire[65537];
    for (unsigned i = 0; i < sizeof(payload); ++i)
        payload[i] = (uint8_t) (i * 17 + 3);
    unsigned sizes[] = {0, 1, 65535, 65536};
    for (unsigned i = 0; i < 4; ++i)
        for (unsigned pad = 0; pad < 2; ++pad)
        {
            begin(true, "127.0.0.1", 128, 0, false);
            establish();
            unsigned n = sizes[i];
            f.t->fnPayloadU(f.t, f.app, bytes(payload, n, pipe && n <= 4096, pad ? 320 : 0));
            if (n == 0 || n > 65535)
                twfRequire(f.deliveries_up == 0 && lineIsAlive(f.app), "invalid local UDP closed association");
            else
            {
                unsigned len = frame(wire, payload, n);
                twfRequire(f.up_len == 26 + len && memcmp(f.up + 26, wire, len) == 0, "UDP framing changed");
                response();
                for (unsigned offset = 0; offset < len;)
                {
                    unsigned chunk = min(2048U, len - offset);
                    f.t->fnPayloadD(f.t, f.carrier, bytes(wire + offset, chunk, pipe, 320));
                    offset += chunk;
                }
                twfRequire(f.deliveries_down == 1 && f.down_len == n && memcmp(f.down, payload, n) == 0,
                           "UDP assembly changed");
                twfRequire(f.headroom >= 320, "onward padding lost");
            }
            end();
        }
}
static void testPressure(void)
{
    twfSetCase("admitted UDP batches complete through Pause with no decoded backlog");
    uint8_t wire[20000];
    for (unsigned close = 0; close < 2; ++close)
    {
        begin(true, "127.0.0.1", 128, 0, false);
        establish();
        response();
        unsigned length = 0;
        for (unsigned i = 0; i < 1500; ++i)
            length += frame(wire + length, "x", 1);
        f.boundary = 5;
        f.action   = close ? 8 : 3;
        f.t->fnPayloadD(f.t, f.carrier, bytes(wire, length, false, 320));
        twfRequire(f.deliveries_down == (close ? 1U : 1500U), "batch paused early or continued after Finish");
        if (! close)
        {
            vlessclient_lstate_t *ls = lineGetState(f.carrier, f.t);
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
    response();
    unsigned length = 0;
    length += frame(wire + length, "A", 1);
    length += frame(wire + length, "B", 1);
    f.boundary = 5;
    f.action   = 10;
    f.t->fnPayloadD(f.t, f.carrier, bytes(wire, length, false, 320));
    twfRequire(f.down_len == 3 && memcmp(f.down, "ABC", 3) == 0, "nested admitted batch overtook older input");
    end();
}
static void testLimits(uint32_t pool_size)
{
    twfSetCase("parser retained-byte equality and one-over refusal");
    for (unsigned udp = 0; udp < 2; ++udp)
    {
        begin(udp, "127.0.0.1", pool_size, 0, false);
        vlessclient_lstate_t *ls    = lineGetState(f.carrier, f.t);
        size_t                limit = udp ? kVlessClientMaxUdpBufferedBytes : kVlessClientMaxTcpWireBytes;
        uint8_t              *data  = memoryAllocateZero(limit);
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
static void testNestedTcpRetention(void)
{
    twfSetCase("body-only nested admission uses exact 2 MiB order bound");
    for (unsigned extra = 0; extra < 2; ++extra)
    {
        begin(false, "127.0.0.1", 128, 0, false);
        f.inject_extra = extra != 0;
        f.boundary     = 5;
        f.action       = 11;
        f.t->fnPayloadD(f.t, f.carrier, bytes("\0\0A", 3, false, 320));
        twfRequire(lineIsAlive(f.app) == ! extra, "nested body-only retention bound changed");
        twfRequire(f.down_len == (extra ? 1U : 1U + kVlessClientMaxOrderBytes),
                   "nested input lost FIFO or survived overflow");
        twfRequire(f.down[0] == 'A' && (extra || f.down[f.down_len - 1] == 'r'), "nested body bytes changed");
        end();
    }
}

static void testFailuresAndClose(void)
{
    twfSetCase("parser admission refusal and Finish at real callback boundaries");
    for (unsigned udp = 0; udp < 2; ++udp)
    {
        if (udp || true)
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
                    if (boundary == 5 && ! false)
                        f.t->fnPayloadD(f.t, f.carrier, bytes("\0\0", 2, false, 320));
                    f.boundary = boundary;
                    f.action   = action;
                    if (boundary == 2 || boundary == 3)
                        establish();
                    if (boundary == 4)
                        f.t->fnPayloadU(f.t, f.app, bytes("A", 1, true, 320));
                    if (boundary == 5)
                        f.t->fnPayloadD(f.t, f.carrier, bytes(udp ? "\0\1C" : "A", udp ? 3 : 1, true, 320));
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
    uint32_t n = frame(wire, payload, sizeof(payload));
    for (unsigned fault = 0; fault < 4; ++fault)
    {
        begin(true, "127.0.0.1", 128, 0, false);
        establish();
        response();
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

static void testSetupAndCallbackBudget(void)
{
    twfSetCase("failed setup and admission during Est");
    begin(false, "127.0.0.1", 128, 0, false);
    f.t->fnFinU(f.t, f.app);
    lineDestroy(f.app);
    lineUnref(f.app);
    f.app = f.carrier = twfLinePoolCreateLine(&f.lines);
    lineRef(f.app);
    vlessclient_tstate_t *ts = tunnelGetState(f.t);
    ts->target_port_source   = kDvsFirstOption;
    f.t->fnInitU(f.t, f.app);
    twfRequire(! lineIsAlive(f.app) && f.finishes == 1 && f.transport_finishes == 1,
               "failed target setup finished an uninitialized next branch");
    end();
}

static void testPrefixes(void)
{
    twfSetCase("prefixes, mixed sources, full padding and unrestricted UDP fragments");
    begin(true, "127.0.0.1", 128, 0, false);
    establish();
    response();
    sbuf_t *b = bytes("body", 4, true, 320);
    sbufShiftLeft(b, 3);
    sbufWrite(b, "pre", 3);
    f.t->fnPayloadU(f.t, f.app, b);
    twfRequire(memcmp(f.up + 26, "\0\7prebody", 9) == 0 && f.parser_reads == 0, "prefix overwritten or materialized");
    b = bytes("body", 4, true, 320);
    sbufShiftLeft(b, 2);
    sbufWrite(b, "\0\4", 2);
    f.t->fnPayloadD(f.t, f.carrier, b);
    twfRequire((! WW_HAVE_SPLICE || f.last == b) && f.parser_reads == 0, "whole body lost identity");
    f.t->fnPayloadD(f.t, f.carrier, bytes("\0\4A", 3, false, 320));
    f.t->fnPayloadD(f.t, f.carrier, bytes("BC", 2, true, 320));
    f.t->fnPayloadD(f.t, f.carrier, bytes("D", 1, false, 320));
    twfRequire(f.down_len == 8 && memcmp(f.down, "bodyABCD", 8) == 0, "mixed assembly changed");
    f.paused_down = true;
    f.t->fnPauseU(f.t, f.app);
    f.t->fnPayloadD(f.t, f.carrier, bytes("\5\334", 2, false, 320));
    for (unsigned i = 0; i < 1500; ++i)
        f.t->fnPayloadD(f.t, f.carrier, bytes("X", 1, false, 320));
    twfRequire(lineIsAlive(f.app), "wire fragments consumed output-entry budget");
    f.paused_down = false;
    f.t->fnResumeU(f.t, f.app);
    twfRequire(f.deliveries_down == 3 && f.down_len == 1508, "fragment boundaries lost");
    end();
    begin(true, "127.0.0.1", 128, 0, false);
    bufferpoolUpdateAllocationPaddings(f.env.pool, 352, 352, 352, 32);
    establish();
    response();
    f.t->fnPayloadD(f.t, f.carrier, bytes("\0\6padded", 8, true, 32));
    twfRequire(f.headroom >= 352 && memcmp(f.down, "padded", 6) == 0, "receive padding lost");
    f.t->fnPayloadU(f.t, f.app, bytes("send", 4, true, 0));
    twfRequire(f.headroom >= 350 && memcmp(f.up + 28, "send", 4) == 0, "send padding lost");
    end();
}
static void testMalformed(void)
{
    twfSetCase("invalid response and incoming empty UDP close only association");
    for (unsigned udp = 0; udp < 2; ++udp)
    {
        begin(udp, "127.0.0.1", 128, 0, false);
        establish();
        f.t->fnPayloadD(f.t, f.carrier, bytes("\1\0", 2, true, 320));
        twfRequire(! lineIsAlive(f.app) && f.down_len == 0, "invalid response survived");
        end();
    }
    begin(true, "127.0.0.1", 128, 0, false);
    establish();
    response();
    f.t->fnPayloadD(f.t, f.carrier, bytes("\0\0", 2, true, 320));
    twfRequire(! lineIsAlive(f.app) && ! lineIsAlive(f.carrier), "zero incoming UDP survived");
    end();
}

static void testNested(void)
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
        twfRequire(f.ests == 1 && f.requests == 1 && f.up_len == 26 + (udp ? 3 : 1),
                   "Est input was split from request");
        end();
        begin(udp, "127.0.0.1", 128, 0, false);
        f.boundary = 2;
        f.action   = 5;
        f.t->fnPayloadU(f.t, f.app, bytes("A", 1, true, 320));
        twfRequire(f.requests == 1 && f.up[28 * udp + 26 * ! udp] == 'A' && f.up[f.up_len - 1] == 'C',
                   "nested payload overtook initial output");
        end();
    }
}
static void testPreparedDestination(void)
{
    twfSetCase("prepare before DNS, resolved destination preserved and UUID aliases");
    for (unsigned udp = 0; udp < 2; ++udp)
    {
        begin(udp, "example.test", 128, 0, true);
        f.t->fnFinU(f.t, f.app);
        lineDestroy(f.app);
        lineUnref(f.app);
        if (udp)
            lineUnref(f.carrier);
        f.app = f.carrier = lineCreate(f.owner_pools, 0);
        lineRef(f.app);
        vlessclient_tstate_t *ts = tunnelGetState(f.t);
        ts->resolve_domains      = true;
        addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(f.app), udp ? IP_PROTO_UDP : IP_PROTO_TCP);
        twfRequire(vlessclientDomainResolverPrepare(NULL, f.t, f.app, NULL), "prepare refused");
        address_context_t *target = lineGetDestinationAddressContext(f.app);
        twfRequire(addresscontextIsDomain(target) && target->port == 443 && target->proto_udp == udp,
                   "target was not prepared before DNS");
        sockaddr_u resolved;
        twfRequire(sockaddrSetIpAddressPort(&resolved, "127.0.0.2", 443) == 0, "resolved address setup failed");
        dns_resolved_addr_t answer = {.family = AF_INET, .addrlen = sizeof(struct sockaddr_in)};
        memcpy(&answer.addr, &resolved, answer.addrlen);
        twfRequire(dnsstrategyApplyResolvedAddress(target, &answer), "DNS application failed");
        f.t->fnInitU(f.t, f.app);
        establish();
        twfRequire(f.up_len == 26 && f.up[18] == (udp ? 2 : 1) && f.up[25] == 2,
                   "Init reapplied configured domain after DNS");
        end();
    }
    const char *aliases[] = {"uuid", "id", "user-id"};
    for (unsigned i = 0; i < 3; ++i)
    {
        begin(false, "127.0.0.1", 128, 0, false);
        cJSON_DeleteItemFromObject(f.node.node_settings_json, "uuid");
        cJSON_AddStringToObject(f.node.node_settings_json, aliases[i], "5783a3e7e37351cd8642c83782b807c5");
        tunnel_t *other = vlessclientTunnelCreate(&f.node);
        twfRequire(other != NULL && memcmp(((vlessclient_tstate_t *) tunnelGetState(other))->uuid,
                                           ((vlessclient_tstate_t *) tunnelGetState(f.t))->uuid,
                                           16) == 0,
                   "UUID alias changed bytes");
        other->onDestroy(other, wwLifecycleStartupRollback());
        end();
    }
}
static void testOwnerDrain(void)
{
    twfSetCase("nonzero worker dependent carrier drain at every barrier");
    test_wid = 1;
    for (unsigned stage = 0; stage < 4; ++stage)
    {
        begin(true, "127.0.0.1", 128, 0, true);
        f.t->fnPayloadU(f.t, f.app, bytes("queued", 6, true, 320));
        if (stage)
            establish();
        if (stage == 2)
            f.t->fnPayloadD(f.t, f.carrier, bytes("\0\377partial", 9, true, 320));
        if (stage == 3)
        {
            response();
            f.paused_down = true;
            f.t->fnPauseU(f.t, f.app);
            f.t->fnPayloadD(f.t, f.carrier, bytes("\0\7partial", 9, true, 320));
        }
        end();
    }
    test_wid = 0;
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
            twfRequire(f.up_len == 26 + (udp ? 2 : 0) + length &&
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
    twfRequire(f.requests == 0, "empty UDP policy changed");
    end();
}

static void testInitialAllocationRefusal(void)
{
    twfSetCase("unrepresentable first-output refusal settles source and waiting timer");
    for (unsigned udp = 0; udp < 2; ++udp)
    {
        begin(udp, "127.0.0.1", 128, 0, false);
        ((vlessclient_tstate_t *) tunnelGetState(f.t))->first_payload_timeout_ms = 400;
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
        tunnel_t *other = vlessclientTunnelCreate(&f.node);
        twfRequire((other != NULL) == (i < 3), "constructor timeout acceptance changed");
        if (other != NULL)
        {
            uint32_t expected = i == 0 ? 0U : i == 1 ? 17U : UINT32_MAX;
            twfRequire(((vlessclient_tstate_t *) tunnelGetState(other))->first_payload_timeout_ms == expected,
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
            ((vlessclient_tstate_t *) tunnelGetState(f.t))->first_payload_timeout_ms = 400;
            establish();
            vlessclient_lstate_t *ls = lineGetState(f.carrier, f.t);
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
                               f.up_len == 26 + (udp ? 2 + 1 : 1),
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
                                   f.up_len == 26 + (mode == 5 ? 0
                                                     : udp     ? 2 + 1
                                                               : 1),
                               "due header duplicated, failed to combine, or failed Resume");
                    f.t->fnResumeD(f.t, f.carrier);
                    twfRequire(f.requests == 1, "duplicate Resume repeated request");
                }
            }
            end();
        }
    begin(false, "127.0.0.1", 128, 0, false);
    ((vlessclient_tstate_t *) tunnelGetState(f.t))->first_payload_timeout_ms = 400;
    wloopCloseNormalAdmission(f.env.loop);
    establish();
    twfRequire(! lineIsAlive(f.app) && f.requests == 0, "timer admission refusal stranded line");
    end();
    begin(false, "127.0.0.1", 128, 0, false);
    ((vlessclient_tstate_t *) tunnelGetState(f.t))->first_payload_timeout_ms = 1;
    establish();
    uint64_t stop = getHRTimeUs() + 1000000;
    while (f.requests == 0 && getHRTimeUs() < stop)
        discard wloopProcessEvents(f.env.loop, 5);
    twfRequire(f.requests == 1 && f.up_len == 26, "real-loop timer did not expire");
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
    tunnel_t *inner = vlessclientTunnelCreate(&f.node);
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
    twfRequire(f.requests == 1 && f.deliveries_up == 0 && ! f.last_splice && f.up_len == length + 556 &&
                   memcmp(f.up + 556, data, length) == 0,
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
    ((vlessclient_tstate_t *) tunnelGetState(f.t))->first_payload_timeout_ms = 400;
    establish();
    vlessclient_lstate_t *ls = lineGetState(f.carrier, f.t);
    twfRequire(lineGetWID(f.carrier) == 1 && ls->first_payload_timer != NULL &&
                   ls->first_payload_timer->loop == f.env.loop && ls->first_payload_timer->loop->wid == 1,
               "timer used foreign worker loop");
    end();
    test_wid = 0;
}

int main(void)
{
    testFirstPayload();
    testInitialAllocationRefusal();
    testTimeoutConfiguration();
    testTimers();
    testTimerWorker();
    testNestedClients();
    testBaseline();
    testTcp(false);
    testTcp(true);
    testRequests();
    testResponse(false);
    testResponse(true);
    testUdp(false);
    testUdp(true);
    testPressure();
    testNestedTcpRetention();
    testLimits(128);
    testLimits(128 * 1024);
    testFailuresAndClose();
    testFallback();
    testSetupAndCallbackBudget();
    testPrefixes();
    testMalformed();
    testNested();
    testPreparedDestination();
    testOwnerDrain();
    puts("VlessClient wire, splice, bounds, pressure and lifetime passed");
    return 0;
}
