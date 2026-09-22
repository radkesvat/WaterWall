#include "tunnel_line_failure_harness.h"

extern tunnel_t *bgp4clientTunnelCreate(node_t *node);
extern tunnel_t *bgp4serverTunnelCreate(node_t *node);

static unsigned  interruption;
static uint32_t  pool_size = SPLICE_PAYLOAD_LIMIT;
static tunnel_t *decoder;
static bool      decoder_receives_upstream;
static void      ownerFinish(tunnel_t *t, line_t *l)
{
    discard t;
    lineDestroy(l);
}
static sbuf_t  *wire;
static uint32_t received;
static uint32_t calls;
static bool     pause_on_delivery;
static uint8_t  pattern(uint32_t i)
{
    return (uint8_t) (i * 31 + 7);
}

static void captureWire(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    if (wire == NULL)
        wire = buf;
    else
    {
        wire = sbufReserveSpace(wire, sbufGetLength(wire) + sbufGetLength(buf));
        sbufMoveTo(wire, buf, sbufGetLength(buf));
        lineReuseBuffer(l, buf);
    }
}
static void receive(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    const uint8_t *p = sbufGetRawPtr(buf);
    for (uint32_t i = 0; i < sbufGetLength(buf); ++i)
        twfRequire(p[i] == pattern(received + i), "roundtrip changed stream bytes");
    received += sbufGetLength(buf);
    ++calls;
    lineReuseBuffer(l, buf);
    if (interruption == 1)
    {
        if (decoder_receives_upstream)
            decoder->fnFinD(decoder, l);
        else
            decoder->fnFinU(decoder, l);
        if (lineIsAlive(l))
            lineDestroy(l);
        return;
    }
    if (pause_on_delivery)
    {
        if (t->prev != NULL)
            tunnelPrevDownStreamPause(t, l);
        else
            tunnelNextUpStreamPause(t, l);
    }
}

static void runCase(bool reverse, uint32_t length, uint32_t fragment)
{
    twf_worker_env_t env;
    twfWorkerEnvSetupWithBufferSizes(
        &env, min(pool_size, (uint32_t) LARGE_BUFFER_SIZE_RAM_HIGH), 4096, 128, pool_size, pool_size);
    cJSON         *settings = cJSON_CreateObject();
    node_t         node     = {.node_settings_json = settings};
    tunnel_t      *client   = bgp4clientTunnelCreate(&node);
    tunnel_t      *server   = bgp4serverTunnelCreate(&node);
    tunnel_chain_t chain    = {.supports_splice = WW_HAVE_SPLICE};
    client->chain = server->chain = &chain;
    twf_trace_t trace             = {0};
    tunnel_t   *cp = twfCreatePrevTunnel(&trace), *cn = twfCreateNextTunnel(&trace);
    tunnel_t   *sp = twfCreatePrevTunnel(&trace), *sn = twfCreateNextTunnel(&trace);
    tunnelBind(cp, client);
    tunnelBind(client, cn);
    tunnelBind(sp, server);
    tunnelBind(server, sn);
    twf_line_pool_t lines;
    twfLinePoolSetup(&lines, max(client->lstate_size, server->lstate_size), 8);
    line_t *cl = twfLinePoolCreateLine(&lines), *sl = twfLinePoolCreateLine(&lines);
    lineRef(cl);
    lineRef(sl);
    cp->fnFinD                = ownerFinish;
    sp->fnFinD                = ownerFinish;
    decoder                   = reverse ? client : server;
    decoder_receives_upstream = ! reverse;
    client->fnInitU(client, cl);
    server->fnInitU(server, sl);
    cn->fnPayloadU = captureWire;
    sp->fnPayloadD = captureWire;
    cp->fnPayloadD = receive;
    sn->fnPayloadU = receive;
    for (unsigned delivery = 0; delivery < 2; ++delivery)
    {
        sbuf_t *input = bufferpoolGetLargeBuffer(env.pool);
        input         = sbufReserveSpace(input, length);
        sbufSetLength(input, length);
        for (uint32_t i = 0; i < length; ++i)
            sbufGetMutablePtr(input)[i] = pattern(i);
        if (reverse)
            server->fnPayloadD(server, sl, input);
        else
            client->fnPayloadU(client, cl, input);
        twfRequire(wire != NULL, "encoder dropped input");
        uint32_t       offset = 0, opens = 0;
        const uint8_t *p = sbufGetRawPtr(wire);
        while (offset < sbufGetLength(wire))
        {
            twfRequire(sbufGetLength(wire) - offset >= 19, "truncated frame header");
            for (unsigned i = 0; i < 16; ++i)
                twfRequire(p[offset + i] == 255, "invalid marker");
            uint32_t body = ((uint32_t) p[offset + 16] << 8) | p[offset + 17];
            twfRequire(body > 1 && body <= sbufGetLength(wire) - offset - 18, "invalid wire length");
            opens += p[offset + 18] == 1;
            offset += 18 + body;
        }
        twfRequire(opens == (! reverse && delivery == 0), "OPEN count is incorrect");
        received = calls  = 0;
        pause_on_delivery = fragment == 0;
        sbuf_t *encoded   = wire;
        wire              = NULL;
        if (interruption == 2)
            sbufGetMutablePtr(encoded)[0] = 0;
        if (fragment == 0)
        {
            if (reverse)
                client->fnPayloadD(client, cl, encoded);
            else
                server->fnPayloadU(server, sl, encoded);
            if (interruption == 1 || interruption == 2)
            {
                twfRequire(! lineIsAlive(reverse ? cl : sl), "decoder interruption did not close through owner");
                twfRequire(calls == (interruption == 1), "malformed frame escaped or close repeated delivery");
                break;
            }
            twfRequire(calls == 1, "decoder sent another callback after Pause");
            pause_on_delivery = false;
            if (reverse)
                client->fnResumeU(client, cl);
            else
                server->fnResumeD(server, sl);
        }
        else
        {
            while (sbufGetLength(encoded) > 0)
            {
                uint32_t n    = min(fragment, sbufGetLength(encoded));
                sbuf_t  *part = sbufCreateWithPadding(n, 128);
                sbufMoveTo(part, encoded, n);
                if (reverse)
                    client->fnPayloadD(client, cl, part);
                else
                    server->fnPayloadU(server, sl, part);
            }
            lineReuseBuffer(cl, encoded);
        }
        twfRequire(received == length, "decoder lost stream bytes");
    }
    if (lineIsAlive(cl))
        client->fnFinU(client, cl);
    if (lineIsAlive(sl))
        server->fnFinU(server, sl);
    twfRequireLineStateZeroed(cl, client, "client retained state after Finish");
    twfRequireLineStateZeroed(sl, server, "server retained state after Finish");
    if (lineIsAlive(cl))
        lineDestroy(cl);
    if (lineIsAlive(sl))
        lineDestroy(sl);
    lineUnref(cl);
    lineUnref(sl);
    twfLinePoolTeardown(&lines);
    tunnelDestroy(cp);
    tunnelDestroy(cn);
    tunnelDestroy(sp);
    tunnelDestroy(sn);
    tunnelDestroy(client);
    tunnelDestroy(server);
    cJSON_Delete(settings);
    twfWorkerEnvTeardown(&env);
}
/* Exercise the actual callbacks with deterministic pipe/queue refusals. */
#include "../../tunnels/Internals/Bgp4Common/stream.h"
#if WW_HAVE_SPLICE
#include <fcntl.h>
#include <unistd.h>
#endif

static bool fail_stream, fail_queue, fail_pipe, pipe_pressure;
#if WW_HAVE_SPLICE
static bool     reject_growth;
static unsigned growth_refusals;
#endif
static uint32_t fixture_splice_limit = 4096;
static int      fixed_random         = -1;
static unsigned pipe_moves;
static size_t   pipe_read_bytes;
uint32_t        __real_fastRand(void);
uint32_t        __wrap_fastRand(void);
uint32_t        __wrap_fastRand(void)
{
    return fixed_random < 0 ? __real_fastRand() : (uint32_t) fixed_random;
}
splice_stream_t *__real_splicestreamCreate(buffer_pool_t *, uint32_t);
splice_stream_t *__wrap_splicestreamCreate(buffer_pool_t *, uint32_t);
splice_stream_t *__wrap_splicestreamCreate(buffer_pool_t *pool, uint32_t header)
{
    return fail_stream ? NULL : __real_splicestreamCreate(pool, header);
}
bool __real_bufferqueueReserveExtra(buffer_queue_t *, size_t);
bool __wrap_bufferqueueReserveExtra(buffer_queue_t *, size_t);
bool __wrap_bufferqueueReserveExtra(buffer_queue_t *q, size_t count)
{
    if (fail_queue)
    {
        fail_queue = false;
        return false;
    }
    return __real_bufferqueueReserveExtra(q, count);
}
#if WW_HAVE_SPLICE
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
    if (command == F_SETPIPE_SZ && reject_growth)
    {
        ++growth_refusals;
        errno = EPERM;
        return -1;
    }
    return __real_fcntl(fd, command, value);
}
int __real_pipe2(int *, int);
int __wrap_pipe2(int *, int);
int __wrap_pipe2(int *fds, int flags)
{
    if (fail_pipe)
    {
        errno = EMFILE;
        return -1;
    }
    int result = __real_pipe2(fds, flags);
    if (result == 0 && reject_growth)
        twfRequire(__real_fcntl(fds[0], F_SETPIPE_SZ, 4096) == 4096, "cannot create one-page pipe fixture");
    return result;
}
ssize_t __real_splice(int, off_t *, int, off_t *, size_t, unsigned);
ssize_t __wrap_splice(int, off_t *, int, off_t *, size_t, unsigned);
ssize_t __wrap_splice(int in, off_t *oi, int out, off_t *oo, size_t count, unsigned flags)
{
    if (pipe_pressure && pipe_moves++ != 0)
    {
        errno = EAGAIN;
        return -1;
    }
    return __real_splice(in, oi, out, oo, pipe_pressure ? min(count, (size_t) 257) : count, flags);
}
ssize_t __real_read(int, void *, size_t);
ssize_t __wrap_read(int, void *, size_t);
ssize_t __wrap_read(int fd, void *out, size_t count)
{
    ssize_t n = __real_read(fd, out, count);
    if (n > 0)
        pipe_read_bytes += (size_t) n;
    return n;
}
#endif

extern node_t nodeBgp4ClientGet(void);
extern node_t nodeBgp4ServerGet(void);
typedef struct bgp_fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  lines;
    tunnel_chain_t  *chain;
    node_t           node;
    tunnel_t        *t, *prev, *next;
    line_t          *line;
    twf_trace_t      trace;
    bool             client, encode;
    unsigned         action, deliveries, pauses, resumes, finishes;
    size_t           length, reads_at_delivery;
    uint8_t         *bytes;
    sbuf_t          *last_buffer;
    int              last_pipe;
    uint32_t         headroom;
} bgp_fixture_t;
static bgp_fixture_t *active;
static void           fixtureSubmit(bgp_fixture_t *, sbuf_t *);
static void           fixturePermission(bgp_fixture_t *, bool);
static uint32_t       makeWire(uint8_t *, uint32_t, bool, unsigned);

static sbuf_t *fixtureBytes(bgp_fixture_t *f, const void *bytes, uint32_t length, bool splice_input)
{
    sbuf_t *b;
#if WW_HAVE_SPLICE
    if (splice_input)
    {
        b = bufferpoolGetSpliceBuffer(f->env.pool);
        twfRequire(b != NULL, "source pipe checkout failed");
        const splice_buffer_metadata_t m = sbufSpliceMetadata(b);
        twfRequire(write(m.pipefd[1], bytes, length) == (ssize_t) length, "small source pipe write failed");
        b->capacity = b->l_pad + length;
    }
    else
#endif
    {
        discard splice_input;
        b = bufferpoolGetBestFit(f->env.pool, length, 128);
        sbufWrite(b, bytes, length);
    }
    sbufSetLength(b, length);
    return b;
}
static void fixtureOwnerFinish(tunnel_t *t, line_t *l)
{
    discard t;
    ++active->finishes;
    lineDestroy(l);
}
static void fixtureProducerPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    twfRequire(t == (active->encode == active->client ? active->prev : active->next), "Pause direction reversed");
    ++active->pauses;
    if (active->action == 7)
    {
        active->action = 0;
        active->t->fnFinD(active->t, l);
    }
}
static void fixtureProducerResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    twfRequire(t == (active->encode == active->client ? active->prev : active->next), "Resume direction reversed");
    ++active->resumes;
    unsigned action = active->action;
    active->action  = 0;
    if (action == 8)
        fixturePermission(active, true);
    if (action == 9)
        active->t->fnFinD(active->t, l);
}
static void fixtureReceive(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard        t;
    bgp_fixture_t *f = active;
    twfRequire(t == (f->encode == f->client ? f->next : f->prev), "Payload direction reversed");
    ++f->deliveries;
    f->last_buffer       = b;
    f->last_pipe         = sbufIsSplice(b) ? sbufSpliceMetadata(b).pipefd[0] : -1;
    f->headroom          = sbufGetLeftCapacity(b);
    f->reads_at_delivery = pipe_read_bytes;
    uint32_t n           = sbufGetLength(b);
    twfRequire(f->length + n <= 4U * 1024 * 1024, "test capture overflow");
    sbufReadRangeToMemory(b, f->bytes + f->length, n);
    f->length += n;
    lineReuseBuffer(l, b);
    const unsigned action = f->action;
    f->action             = 0;
    if (action == 1 || action == 2 || action == 5)
        fixturePermission(f, true);
    if (action == 2)
        fixturePermission(f, false);
    if (action == 3 || action == 5)
    {
        uint8_t value = 0xee;
        fixtureSubmit(f, fixtureBytes(f, &value, 1, false));
    }
    if (action == 6)
    {
        uint8_t frame[20];
        makeWire(frame, 1, false, 0);
        frame[19] = 0xee;
        fixtureSubmit(f, fixtureBytes(f, frame, sizeof(frame), false));
    }
    if (action == 4)
    {
        f->t->fnFinD(f->t, l);
    }
}
static void fixtureBegin(bgp_fixture_t *f, bool client, bool encode, uint32_t large)
{
    memoryZero(f, sizeof(*f));
    active    = f;
    f->client = client;
    f->encode = encode;
    twfWorkerEnvSetupWithBufferSizes(&f->env, large, 4096, 128, fixture_splice_limit, large);
    f->node = client ? nodeBgp4ClientGet() : nodeBgp4ServerGet();
    twfRequire((f->node.flags & kNodeFlagSupportsSplice) != 0 && f->node.required_padding_left == (client ? 39 : 19),
               "BGP capability/padding metadata changed");
    f->node.node_settings_json = cJSON_CreateObject();
    f->t                       = client ? bgp4clientTunnelCreate(&f->node) : bgp4serverTunnelCreate(&f->node);
    f->prev                    = twfCreatePrevTunnel(&f->trace);
    f->next                    = twfCreateNextTunnel(&f->trace);
    tunnelBind(f->prev, f->t);
    tunnelBind(f->t, f->next);
    f->chain                  = memoryAllocateZero(sizeof(tunnel_chain_t));
    f->chain->supports_splice = WW_HAVE_SPLICE;
    f->t->chain               = f->chain;
    twfLinePoolSetup(&f->lines, f->t->lstate_size, 8);
    f->line = twfLinePoolCreateLine(&f->lines);
    lineRef(f->line);
    f->prev->fnFinD     = fixtureOwnerFinish;
    f->prev->fnPayloadD = f->next->fnPayloadU = fixtureReceive;
    f->prev->fnPauseD = f->next->fnPauseU = fixtureProducerPause;
    f->prev->fnResumeD = f->next->fnResumeU = fixtureProducerResume;
    f->bytes                                = memoryAllocate(4U * 1024 * 1024);
    f->t->fnInitU(f->t, f->line);
}
static void fixtureEnd(bgp_fixture_t *f)
{
    if (lineIsAlive(f->line))
    {
        f->t->fnFinU(f->t, f->line);
        lineDestroy(f->line);
    }
    twfRequireLineStateZeroed(f->line, f->t, "BGP teardown retained resources");
    lineUnref(f->line);
    twfLinePoolTeardown(&f->lines);
    tunnelDestroy(f->prev);
    tunnelDestroy(f->next);
    tunnelDestroy(f->t);
    memoryFree(f->chain);
    cJSON_Delete(f->node.node_settings_json);
    memoryFree(f->node.type);
    memoryFree(f->bytes);
    twfRequireNoLeakedBuffers();
    twfWorkerEnvTeardown(&f->env);
}
static void fixtureSubmit(bgp_fixture_t *f, sbuf_t *b)
{
    if (f->encode == f->client)
        f->t->fnPayloadU(f->t, f->line, b);
    else
        f->t->fnPayloadD(f->t, f->line, b);
}
static void fixturePermission(bgp_fixture_t *f, bool pause)
{
    if (f->encode == f->client)
    {
        if (pause)
            f->t->fnPauseD(f->t, f->line);
        else
            f->t->fnResumeD(f->t, f->line);
    }
    else
    {
        if (pause)
            f->t->fnPauseU(f->t, f->line);
        else
            f->t->fnResumeU(f->t, f->line);
    }
}
static uint32_t makeWire(uint8_t *wire_bytes, uint32_t payload, bool open, unsigned optional)
{
    const uint32_t extra = open ? 10 + optional : 0;
    memorySet(wire_bytes, 0xff, 16);
    const uint32_t length = 1 + extra + payload;
    twfRequire(length <= UINT16_MAX, "invalid test frame length");
    wire_bytes[16] = (uint8_t) (length >> 8);
    wire_bytes[17] = (uint8_t) length;
    wire_bytes[18] = open ? 1 : 2;
    if (open)
    {
        memoryZero(wire_bytes + 19, extra);
        wire_bytes[19] = 4;
        wire_bytes[28] = (uint8_t) optional;
    }
    for (uint32_t i = 0; i < payload; ++i)
        wire_bytes[19 + extra + i] = pattern(i);
    return 19 + extra + payload;
}
static void checkEncoded(bgp_fixture_t *f, uint32_t application, bool extra)
{
    size_t   offset = 0;
    uint32_t count = 0, opens = 0;
    while (offset < f->length)
    {
        uint8_t *h = f->bytes + offset;
        for (unsigned i = 0; i < 16; ++i)
            twfRequire(h[i] == 255, "encoded marker changed");
        uint32_t length = ((uint32_t) h[16] << 8) | h[17];
        twfRequire(length > 1 && offset + 18 + length <= f->length, "encoded frame truncated");
        uint32_t start = 19;
        if (h[18] == 1)
        {
            ++opens;
            twfRequire(offset == 0 && h[19] == 4, "OPEN repeated or version changed");
            start += 10 + h[28];
        }
        else
            twfRequire(h[18] >= 2 && h[18] <= 5, "invalid encoded type");
        for (uint32_t i = start; i < length + 18; ++i, ++count)
            twfRequire(h[i] == (extra && count == application ? 0xee : pattern(count)), "frame order or bytes changed");
        offset += 18 + length;
    }
    twfRequire(opens == (unsigned) f->client && count == application + extra, "OPEN/body count incorrect");
}
static void testDecodeIdentity(void)
{
    for (unsigned client = 0; client < 2; ++client)
        for (unsigned enabled = 0; enabled < 2; ++enabled)
        {
            bgp_fixture_t f;
            fixtureBegin(&f, client, false, 8192);
            f.chain->supports_splice = enabled && WW_HAVE_SPLICE;
            uint8_t  bytes[1100];
            uint32_t n      = makeWire(bytes, 1000, ! client, 3);
            sbuf_t  *input  = fixtureBytes(&f, bytes, n, WW_HAVE_SPLICE);
            int      fd     = WW_HAVE_SPLICE ? sbufSpliceMetadata(input).pipefd[0] : -1;
            pipe_read_bytes = 0;
            fixtureSubmit(&f, input);
            twfRequire(f.length == 1000 && f.deliveries == 1, "direct decode lost a body");
#if WW_HAVE_SPLICE
            if (enabled)
                twfRequire(f.last_buffer == input && f.last_pipe == fd && f.reads_at_delivery == (client ? 19U : 32U),
                           "direct decoder unnecessarily materialized application bytes");
            else
                twfRequire(f.last_pipe == -1, "disabled chain selected private-pipe output");
#else
            discard fd;
#endif
            fixtureEnd(&f);
        }
    bgp_fixture_t f;
    fixtureBegin(&f, false, true, 8192);
    fixtureSubmit(&f, fixtureBytes(&f, "x", 1, false));
    twfRequire(! ((bgp_stream_t *) lineGetState(f.line, f.t))->open, "reverse output consumed server OPEN state");
    f.encode = false;
    f.length = f.deliveries = 0;
    uint8_t  bytes[64];
    uint32_t n = makeWire(bytes, 2, true, 3);
    fixtureSubmit(&f, fixtureBytes(&f, bytes, n, false));
    twfRequire(f.length == 2 && lineIsAlive(f.line), "early reverse output broke first incoming OPEN");
    fixtureEnd(&f);
}

static void testEncodePressure(void)
{
    uint8_t *data = memoryAllocate(1024 * 1024);
    for (uint32_t i = 0; i < 1024 * 1024; ++i)
        data[i] = pattern(i);
    for (unsigned client = 0; client < 2; ++client)
        for (unsigned action = 1; action <= 5; ++action)
        {
            bgp_fixture_t f;
            fixtureBegin(&f, client, true, 8192);
            f.action = action;
            fixtureSubmit(&f, fixtureBytes(&f, data, 1024 * 1024, false));
            if (action == 4)
                twfRequire(! lineIsAlive(f.line) && f.deliveries == 1, "Finish did not stop batch");
            else
            {
                if (action == 1 || action == 5)
                {
                    twfRequire(f.deliveries == 1 && f.pauses == 1 && f.resumes == 0, "encoder ignored Pause");
                    fixturePermission(&f, true);
                    fixturePermission(&f, false);
                    fixturePermission(&f, false);
                    twfRequire(f.pauses == 1 && f.resumes == 1, "duplicate or stale pressure notification");
                }
                checkEncoded(&f, 1024 * 1024, action == 3 || action == 5);
            }
            fixtureEnd(&f);
        }
    for (unsigned optional = 3; optional <= 10; ++optional)
        for (unsigned delta = 0; delta < 3; ++delta)
        {
            fixed_random          = (int) optional - 3;
            const uint32_t length = kBgpMaxApplication - 10 - optional - 1 + delta;
            bgp_fixture_t  f;
            fixtureBegin(&f, true, true, 8192);
            fixtureSubmit(&f, fixtureBytes(&f, data, length, false));
            twfRequire(f.bytes[28] == optional && f.deliveries == (delta == 2 ? 2U : 1U), "actual OPEN limit not used");
            checkEncoded(&f, length, false);
            fixtureEnd(&f);
        }
    fixed_random = -1;
    memoryFree(data);
}
static void testDirectRepresentations(void)
{
    for (unsigned client = 0; client < 2; ++client)
        for (unsigned splice_input = 0; splice_input <= WW_HAVE_SPLICE; ++splice_input)
        {
            bgp_fixture_t f;
            fixtureBegin(&f, client, true, 8192);
            fixtureSubmit(&f, fixtureBytes(&f, "", 0, splice_input));
            twfRequire(f.deliveries == 0 && ! ((bgp_stream_t *) lineGetState(f.line, f.t))->open,
                       "empty input used OPEN");
            uint8_t body[100];
            for (unsigned i = 0; i < sizeof(body); ++i)
                body[i] = pattern(i);
            sbuf_t *input = fixtureBytes(&f, body + 5, sizeof(body) - 5, splice_input);
            sbufShiftLeft(input, 5);
            sbufWrite(input, body, 5);
            int fd          = splice_input ? sbufSpliceMetadata(input).pipefd[0] : -1;
            pipe_read_bytes = 0;
            fixtureSubmit(&f, input);
            twfRequire(f.last_buffer == input && f.last_pipe == fd && f.reads_at_delivery == 0,
                       "single-frame encoding replaced input or materialized its body");
            uint32_t overhead = client ? 29 + f.bytes[28] : 19;
            twfRequire(f.headroom == 128 - 5 - overhead, "encoding spent unexpected padding");
            checkEncoded(&f, 100, false);
            fixtureEnd(&f);
        }
}
static void testDecodeFragments(void)
{
    uint8_t bytes[65553];
    for (unsigned client = 0; client < 2; ++client)
        for (unsigned optional = 0; optional <= 255; optional += 255)
        {
            uint32_t n = makeWire(bytes, 100, ! client, optional);
            for (uint32_t split = 1; split < n; ++split)
            {
                bgp_fixture_t f;
                fixtureBegin(&f, client, false, 8192);
                fixtureSubmit(&f, fixtureBytes(&f, bytes, split, WW_HAVE_SPLICE && split % 2));
                twfRequire(f.deliveries == 0, "incomplete frame escaped");
                fixtureSubmit(&f, fixtureBytes(&f, bytes + split, n - split, WW_HAVE_SPLICE && ! (split % 2)));
                twfRequire(f.length == 100 && f.deliveries == 1, "split header/OPEN lost bytes");
                for (unsigned i = 0; i < 100; ++i)
                    twfRequire(f.bytes[i] == pattern(i), "split OPEN bytes changed");
                fixtureEnd(&f);
            }
        }
    for (unsigned client = 0; client < 2; ++client)
    {
        bgp_fixture_t f;
        fixtureBegin(&f, client, false, 8192);
        uint32_t n = makeWire(bytes, kBgpMaxApplication - (client ? 0 : 265), ! client, 255);
        for (uint32_t i = 0; i < n; ++i)
            fixtureSubmit(&f, fixtureBytes(&f, bytes + i, 1, false));
        twfRequire(f.deliveries == 1, "byte-at-a-time maximum frame failed with small pools");
        fixtureEnd(&f);
    }
}
static void testDecodePressureAndFallback(void)
{
    uint8_t bytes[70000];
    for (unsigned client = 0; client < 2; ++client)
        for (unsigned mode = 0; mode < 4; ++mode)
        {
            bgp_fixture_t f;
            fixtureBegin(&f, client, false, 8192);
            uint32_t n  = makeWire(bytes, 60000, ! client, 255);
            uint32_t n2 = makeWire(bytes + n, 99, false, 0);
            memcpy(bytes + n + n2, bytes + n, 7);
            f.action = mode == 3 ? 4 : mode == 2 ? 2 : 1;
            fixturePermission(&f, true);
            for (uint32_t i = 0; i < n + n2 + 7;)
            {
                uint32_t chunk = min(4096U, n + n2 + 7 - i);
                fixtureSubmit(&f, fixtureBytes(&f, bytes + i, chunk, WW_HAVE_SPLICE && (i / 4096) % 2 == 0));
                i += chunk;
            }
            fail_pipe     = mode == 0;
            pipe_pressure = mode == 1;
            pipe_moves    = 0;
            fixturePermission(&f, false);
            fail_pipe = pipe_pressure = false;
            if (mode == 3)
                twfRequire(! lineIsAlive(f.line) && f.deliveries == 1, "decoder continued after Finish");
            else
            {
                if (mode < 2)
                {
                    twfRequire(f.deliveries == 1 && f.last_pipe == -1,
                               "decoder ignored Pause or failed ordinary fallback");
#if WW_HAVE_SPLICE
                    if (mode == 1)
                        twfRequire(pipe_moves >= 2, "fallback did not follow partial pipe progress");
#endif
                    fixturePermission(&f, false);
                }
                twfRequire(f.length == 60099 && f.resumes >= 1,
                           "decoder stranded complete frames or incomplete-header Resume");
                for (unsigned i = 0; i < 60000; ++i)
                    twfRequire(f.bytes[i] == pattern(i), "mixed fallback changed bytes");
                for (unsigned i = 0; i < 99; ++i)
                    twfRequire(f.bytes[60000 + i] == pattern(i), "second frame reordered");
            }
            fixtureEnd(&f);
        }
}
static void testDecoderReentry(void)
{
    for (unsigned client = 0; client < 2; ++client)
    {
        bgp_fixture_t f;
        fixtureBegin(&f, client, false, 8192);
        uint8_t  wire_bytes[256];
        uint32_t n = makeWire(wire_bytes, 100, ! client, 3);
        n += makeWire(wire_bytes + n, 99, false, 0);
        f.action = 6;
        fixtureSubmit(&f, fixtureBytes(&f, wire_bytes, n, false));
        twfRequire(f.length == 200 && f.deliveries == 3 && f.bytes[199] == 0xee,
                   "reentrant decode overtook older frames");
        for (unsigned i = 0; i < 99; ++i)
            twfRequire(f.bytes[100 + i] == pattern(i), "older frame reordered");
        fixtureEnd(&f);
    }
}

static void testEncoderPipeFallback(void)
{
#if WW_HAVE_SPLICE
    for (unsigned client = 0; client < 2; ++client)
        for (unsigned refuse = 0; refuse < 2; ++refuse)
        {
            bgp_fixture_t f;
            fixture_splice_limit = 1024 * 1024;
            reject_growth        = true;
            growth_refusals      = 0;
            fixtureBegin(&f, client, true, 8192);
            /* A large real prefix plus one page of pipe data exercises splitting
             * even on hosts that cannot grant a large pipe. Leave 39 header bytes. */
            const uint32_t prefix = 65504 - 39, body = 4096;
            sbuf_t        *input = twfTrackAcquired(sbufCreateSplice(65504));
            twfRequire(sbufSpliceInitPipe(input, 1024 * 1024) == 0, "source pipe creation failed");
            uint8_t bytes[4096];
            for (uint32_t i = 0; i < body; ++i)
                bytes[i] = pattern(prefix + i);
            twfRequire(write(sbufSpliceMetadata(input).pipefd[1], bytes, body) == body, "source pipe fill failed");
            input->capacity = input->l_pad + body;
            sbufSetLength(input, body);
            sbufShiftLeft(input, prefix);
            for (uint32_t i = 0; i < prefix; ++i)
                sbufGetMutablePtr(input)[i] = pattern(i);
            fail_pipe = refuse != 0;
            fixtureSubmit(&f, input);
            fail_pipe = false;
            twfRequire(f.deliveries == 2 && growth_refusals != 0, "split/refused growth path was not exercised");
            checkEncoded(&f, prefix + body, false);
            fixtureEnd(&f);
            reject_growth        = false;
            fixture_splice_limit = 4096;
        }
#endif
}

static void testNotificationReentry(void)
{
    for (unsigned client = 0; client < 2; ++client)
        for (unsigned encode = 0; encode < 2; ++encode)
            for (unsigned action = 7; action <= 9; ++action)
            {
                bgp_fixture_t f;
                fixtureBegin(&f, client, encode, 8192);
                if (action == 7)
                    f.action = action;
                fixturePermission(&f, true);
                if (action != 7)
                {
                    f.action = action;
                    fixturePermission(&f, false);
                }
                if (action == 8)
                {
                    twfRequire(lineIsAlive(f.line) && f.pauses == 2 && f.resumes == 1,
                               "reentrant Pause during producer Resume lost final permission");
                    fixturePermission(&f, false);
                    twfRequire(f.resumes == 2, "producer stranded after reentrant Pause");
                }
                else
                    twfRequire(! lineIsAlive(f.line) && f.finishes == 1, "notification continued after owner death");
                fixtureEnd(&f);
            }
    for (unsigned client = 0; client < 2; ++client)
    {
        bgp_fixture_t f;
        fail_stream = true;
        fixtureBegin(&f, client, false, 8192);
        fail_stream = false;
        twfRequire(! lineIsAlive(f.line) && f.trace.next_init == 0 && f.trace.next_finish == 0,
                   "failed stream initialization reached uninitialized neighbour");
        fixtureEnd(&f);
        fixtureBegin(&f, client, false, 8192);
        sbuf_t *input = fixtureBytes(&f, "x", 1, false);
        fail_queue    = true;
        fixtureSubmit(&f, input);
        twfRequire(! lineIsAlive(f.line) && f.finishes == 1, "receive admission failure did not close locally");
        fixtureEnd(&f);
    }
}

static void testMalformed(void)
{
    for (unsigned client = 0; client < 2; ++client)
        for (unsigned kind = 0; kind < (client ? 4U : 8U); ++kind)
        {
            bgp_fixture_t f;
            fixtureBegin(&f, client, false, 8192);
            uint8_t  bytes[64];
            uint32_t n = makeWire(bytes, 2, ! client, 3);
            if (kind == 0)
                bytes[0] = 0;
            if (kind == 1)
                bytes[18] = client ? 1 : 2;
            if (kind == 2)
            {
                bytes[16] = 0;
                bytes[17] = 1;
            }
            if (kind == 3)
                bytes[18] = 6;
            if (kind == 4)
                bytes[19] = 3;
            if (kind == 5)
                bytes[28] = 255;
            if (kind == 6)
            {
                bytes[17] = 14;
                n -= 2;
            }
            if (kind == 7)
            {
                bytes[17] = 11;
                n         = 29;
            }
            fixtureSubmit(&f, fixtureBytes(&f, bytes, n, WW_HAVE_SPLICE));
            twfRequire(! lineIsAlive(f.line) && f.finishes == 1 && f.deliveries == 0,
                       "malformed input escaped validation");
            fixtureEnd(&f);
        }
}
static void testAdmission(void)
{
    twfRequire(kBgpPendingBytes == 2162705 && kBgpMaxWireFrame == 65553 && kBgpOutputEntries == 1024,
               "fixed BGP bounds changed");
    for (unsigned client = 0; client < 2; ++client)
        for (unsigned mode = 0; mode < 4; ++mode)
        {
            bgp_fixture_t f;
            fixtureBegin(&f, client, true, mode % 2 ? 65536 : 131072);
            fixturePermission(&f, true);
            if (mode == 0)
            {
                fixed_random          = 0;
                const uint32_t length = kBgpPendingBytes - 33 * 19 - (client ? 13 : 0);
                sbuf_t        *b      = bufferpoolGetBestFit(f.env.pool, length, 128);
                sbufSetLength(b, length);
                fixtureSubmit(&f, b);
                fixed_random = -1;
                twfRequire(bufferqueueGetBufLen(&((bgp_stream_t *) lineGetState(f.line, f.t))->output) ==
                               kBgpPendingBytes,
                           "exact encoded byte boundary refused");
            }
            else if (mode < 3)
            {
                unsigned count = mode == 1 ? 1024 : 1023;
                for (unsigned i = 0; i < count; ++i)
                    fixtureSubmit(&f, fixtureBytes(&f, "x", 1, false));
                twfRequire(lineIsAlive(f.line), "valid output-entry boundary refused");
            }
            else
                fail_queue = true;
            uint32_t extra = mode == 2 ? 65535 : 1;
            sbuf_t  *b     = bufferpoolGetBestFit(f.env.pool, extra, 128);
            sbufSetLength(b, extra);
            fixtureSubmit(&f, b);
            twfRequire(! lineIsAlive(f.line) && f.deliveries == 0 && f.finishes == 1, "batch refusal published output");
            fixtureEnd(&f);
        }
    for (unsigned client = 0; client < 2; ++client)
    {
        bgp_fixture_t f;
        fixtureBegin(&f, client, false, 8192);
        fixturePermission(&f, true);
        uint8_t *bytes = memoryAllocate(kBgpPendingBytes);
        uint32_t used  = 0;
        while (used < kBgpPendingBytes)
        {
            uint32_t frame = min((uint32_t) kBgpMaxWireFrame, kBgpPendingBytes - used);
            bool     open  = ! client && used == 0;
            used += makeWire(bytes + used, frame - 19 - (open ? 13 : 0), open, 3);
        }
        fixtureSubmit(&f, fixtureBytes(&f, bytes, used, false));
        memoryFree(bytes);
        twfRequire(lineIsAlive(f.line) &&
                       splicestreamLength(((bgp_stream_t *) lineGetState(f.line, f.t))->read_stream) ==
                           kBgpPendingBytes,
                   "exact decoder byte boundary refused");
        fixtureSubmit(&f, fixtureBytes(&f, "x", 1, false));
        twfRequire(! lineIsAlive(f.line) && f.deliveries == 0, "decoder overflow escaped");
        fixtureEnd(&f);
    }
    fail_stream = true;
    bgp_fixture_t f;
    fixtureBegin(&f, true, false, 8192);
    fail_stream = false;
    twfRequire(! lineIsAlive(f.line) && f.trace.next_init == 0 && f.trace.next_finish == 0,
               "failed Init called uninitialized next node");
    fixtureEnd(&f);
#if WW_HAVE_SPLICE
    fixtureBegin(&f, true, false, 8192);
    fixturePermission(&f, true);
    uint8_t  bytes[2048];
    uint32_t n = makeWire(bytes, 1500, false, 0);
    for (uint32_t i = 0; i < n; ++i)
        fixtureSubmit(&f, fixtureBytes(&f, bytes + i, 1, true));
    twfRequire(lineIsAlive(f.line), "incoming fragments hit output entry cap");
    fixturePermission(&f, false);
    twfRequire(f.length == 1500, "many pipe fragments failed extraction");
    fixtureEnd(&f);
#endif
}

int main(void)
{
    twfRequire(globalstateInitializeSecureRandom(), "secure random initialization failed");
    twfRequire(frandGlobalInit(), "random initialization failed");
    const uint32_t lengths[] = {65533, 65534, 65535, 128 * 1024, SPLICE_PAYLOAD_LIMIT};
    for (unsigned direction = 0; direction < 2; ++direction)
        for (unsigned i = 0; i < ARRAY_SIZE(lengths); ++i)
        {
            runCase(direction != 0, lengths[i], 0);
            runCase(direction != 0, lengths[i], 65521);
        }
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        runCase(direction != 0, 128, 1);
        for (interruption = 1; interruption <= 2; ++interruption)
            runCase(direction != 0, SPLICE_PAYLOAD_LIMIT, 0);
        interruption = 0;
    }
    pool_size = 32768;
    runCase(false, SPLICE_PAYLOAD_LIMIT, 65521);
    runCase(true, SPLICE_PAYLOAD_LIMIT, 65521);
    testDirectRepresentations();
    testDecodeIdentity();
    testEncodePressure();
    testDecodeFragments();
    testDecodePressureAndFallback();
    testDecoderReentry();
    testEncoderPipeFallback();
    testNotificationReentry();
    testMalformed();
    testAdmission();
    frandThreadCleanup();
    frandGlobalCleanup();
    return 0;
}
