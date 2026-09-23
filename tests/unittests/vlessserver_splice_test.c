#include "AuthenticationClient/interface.h"
#include "VlessServer/interface.h"
#include "VlessServer/structure.h"
#include "fallback_finish_lifetime_fixture.h"

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

static unsigned              auth_calls;
static bool                  auth_available = true, auth_match = true;
authenticationclient_state_t __wrap_authenticationclientGetState(tunnel_t *t);
authenticationclient_state_t __wrap_authenticationclientGetState(tunnel_t *t)
{
    discard t;
    return auth_available ? kAuthenticationClientStateReady : kAuthenticationClientStateStopped;
}
authenticationclient_user_lookup_result_t __wrap_authenticationclientGetUserByUUIDWithProfile(
    tunnel_t *t, const uint8_t *hash, user_handle_t *handle, authenticationclient_user_profile_t *profile);
authenticationclient_user_lookup_result_t __wrap_authenticationclientGetUserByUUIDWithProfile(
    tunnel_t *t, const uint8_t *hash, user_handle_t *handle, authenticationclient_user_profile_t *profile)
{
    discard t;
    discard hash;
    ++auth_calls;
    if (! auth_match)
        return kAuthenticationClientUserLookupUserNotFound;
    userHandleSet(handle, 1, 42);
    profile->name     = stringDuplicate("alice");
    profile->password = stringDuplicate("test");
    return kAuthenticationClientUserLookupOk;
}

typedef struct fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  lines;
    twf_trace_t      trace;
    tunnel_chain_t  *chain;
    node_t           metadata;
    tunnel_t        *t, *prev, *next, *fallback;
    line_t          *line, *remotes[16];
    unsigned         remote_count, inits, ests, finishes, branch_finishes, fallback_inits;
    unsigned         calls_up, calls_down, calls_fallback, pauses, resumes;
    unsigned         action, boundary;
    sbuf_t          *nested;
    unsigned         admission_entries;
    uint32_t         admission_bytes;
    bool             overflow_admission;
    bool             auto_est, down_paused, database;
    uint8_t          up[3 * 1024 * 1024], down[3 * 1024 * 1024], replay[3 * 1024 * 1024];
    size_t           up_len, down_len, replay_len, parser_reads;
    sbuf_t          *last;
    bool             last_splice;
    uint16_t         headroom;
    uint16_t         ports[8192];
} fixture_t;
static fixture_t     f;
static const uint8_t uuid[16] = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
static sbuf_t *bytes(const void *data, uint32_t n, bool pipe, uint16_t padding)
{
    sbuf_t *b;
#if WW_HAVE_SPLICE
    if (pipe)
    {
        b = padding == 320 ? bufferpoolGetSpliceBuffer(f.env.pool) : twfTrackAcquired(sbufCreateSplice(padding));
        twfRequire(b != NULL && sbufSpliceInitPipe(b, 4096) == 0, "source pipe allocation failed");
        twfRequire(write(sbufSpliceMetadata(b).pipefd[1], data, n) == (ssize_t) n, "source pipe fixture too large");
        b->capacity = b->l_pad + n;
    }
    else
#endif
    {
        discard pipe;
        b = padding == 320 ? bufferpoolGetBestFit(f.env.pool, n, padding)
                           : twfTrackAcquired(sbufCreateWithPadding(n, padding));
        if (n != 0)
            sbufWrite(b, data, n);
    }
    sbufSetLength(b, n);
    return b;
}
static uint32_t request(uint8_t *out, unsigned form, bool udp)
{
    memset(out, 0, 278);
    memcpy(out + 1, uuid, 16);
    out[18] = udp ? 2 : 1;
    out[19] = 1;
    out[20] = 0xbb;
    if (form == 0)
    {
        out[21] = 1;
        out[22] = 127;
        out[25] = 1;
        return 26;
    }
    if (form == 1)
    {
        out[21] = 3;
        out[37] = 1;
        return 38;
    }
    out[21] = 2;
    out[22] = form == 2 ? 1 : 255;
    memset(out + 23, 'a', out[22]);
    return 23U + out[22];
}
static uint32_t frame(uint8_t *out, const void *body, uint32_t len)
{
    out[0] = (uint8_t) (len >> 8);
    out[1] = (uint8_t) len;
    if (len != 0)
        memcpy(out + 2, body, len);
    return 2 + len;
}
static void act(unsigned boundary, line_t *l)
{
    if (boundary != f.boundary)
        return;
    unsigned action = f.action;
    f.action        = 0;
    if (action == 1 || action == 2)
    {
        f.t->fnPauseD(f.t, l);
        if (action == 2)
            f.t->fnResumeD(f.t, l);
    }
    if (action == 3 || action == 4)
    {
        f.down_paused = true;
        f.t->fnPauseU(f.t, f.line);
        if (action == 4)
        {
            f.down_paused = false;
            f.t->fnResumeU(f.t, f.line);
        }
    }
    if (action == 5)
        f.t->fnPayloadU(f.t, f.line, bytes("C", 1, false, 320));
    if (action == 6)
        f.t->fnPayloadD(f.t, l, bytes("Z", 1, true, 320));
    if (action == 7)
    {
        f.t->fnFinU(f.t, f.line);
        twfRequire(lineIsAlive(f.line), "server destroyed borrowed client");
        lineDestroy(f.line);
    }
    if (action == 8)
        f.t->fnFinD(f.t, l);
    if (action == 9 && f.remote_count > 1)
    {
        line_t *target = f.remotes[1];
        if (boundary == 7 && target == l && f.remote_count > 2)
            target = f.remotes[2];
        if (lineIsAlive(target))
            f.t->fnFinD(f.t, target);
    }
    if (action == 10)
        f.t->fnEstD(f.t, l);
    if (action == 11)
    {
        sbuf_t *nested = f.nested;
        f.nested       = NULL;
        f.t->fnPayloadU(f.t, f.line, nested);
    }
    if (action == 12)
    {
        uint8_t *data = memoryAllocateZero(f.admission_bytes);
        for (unsigned i = 0; i < f.admission_entries; ++i)
            f.t->fnPayloadU(f.t, f.line, bytes(data, f.admission_bytes, false, 320));
        twfRequire(lineIsAlive(f.line), "exact reentry retention budget rejected");
        if (f.overflow_admission)
        {
            f.t->fnPayloadU(f.t, f.line, bytes(data, f.admission_bytes == 0 ? 0 : 1, false, 320));
            twfRequire(! lineIsAlive(f.line), "reentry retention overflow accepted");
        }
        memoryFree(data);
    }
    if (action == 13)
    {
        for (unsigned i = 0; i < f.remote_count; ++i)
        {
            if (f.remotes[i] != l && lineIsAlive(f.remotes[i]))
            {
                f.t->fnPayloadD(f.t, f.remotes[i], bytes("late", 4, true, 320));
                f.t->fnEstD(f.t, f.remotes[i]);
                break;
            }
        }
    }
}
static void capture(tunnel_t *t, line_t *l, sbuf_t *b)
{
    uint32_t n = sbufGetLength(b);
    uint8_t *out;
    size_t  *length;
    unsigned boundary;
    if (t == f.prev)
    {
        twfRequire(l == f.line, "reply used backend line");
        out    = f.down;
        length = &f.down_len;
        ++f.calls_down;
        boundary = 4;
    }
    else
    {
        if (t == f.fallback)
        {
            out    = f.replay;
            length = &f.replay_len;
            ++f.calls_fallback;
        }
        else
        {
            out                   = f.up;
            length                = &f.up_len;
            f.ports[f.calls_up++] = lineGetDestinationAddressContext(l)->port;
        }
        boundary = 3;
    }
    f.parser_reads += reads;
    reads         = 0;
    f.last        = b;
    f.last_splice = sbufIsSplice(b);
    f.headroom    = (uint16_t) sbufGetLeftCapacity(b);
    twfRequire(*length + n <= sizeof(f.up), "capture overflow");
    sbufReadRangeToMemory(b, out + *length, n);
    reads = 0;
    *length += n;
    lineReuseBuffer(l, b);
    act(boundary, l);
}
static void ownerFinish(tunnel_t *t, line_t *l)
{
    discard t;
    ++f.finishes;
    twfRequire(l == f.line, "server finished client side on backend line");
    lineDestroy(l);
}
static void branchFinish(tunnel_t *t, line_t *l)
{
    discard t;
    ++f.branch_finishes;
    act(7, l);
}
static void onEst(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == f.line, "backend Est escaped association");
    ++f.ests;
    act(2, l);
}
static void onPause(tunnel_t *t, line_t *l)
{
    discard t;
    ++f.pauses;
    act(5, l);
}
static void onResume(tunnel_t *t, line_t *l)
{
    discard t;
    ++f.resumes;
    act(6, l);
}
static void onInit(tunnel_t *t, line_t *l)
{
    if (t == f.fallback)
    {
        ++f.fallback_inits;
        twfRequire(! lineIsAuthenticated(l), "fallback received protected credentials");
    }
    else
    {
        ++f.inits;
        twfRequire(
            lineHasAuthenticatedCredentials(l, "alice", f.database ? "test" : "42424242-4242-4242-4242-424242424242"),
            "protected branch lost credentials");
        if (f.database)
            twfRequire(lineGetCurrentUser(l)->user_id == 42, "database user handle lost");
        if (l != f.line)
        {
            twfRequire(f.remote_count < 16, "backend fixture full");
            lineRef(l);
            f.remotes[f.remote_count++] = l;
        }
    }
    act(1, l);
    if (lineIsAlive(l) && ((vlessserver_lstate_t *) lineGetState(l, f.t))->phase != kVlessServerPhaseClosing &&
        f.auto_est)
        f.t->fnEstD(f.t, l);
}
static void begin(bool fallback, bool database, uint32_t pool)
{
    memoryZero(&f, sizeof(f));
    fail_queue = fail_pipe = pressure = reject_growth = false;
    moves = pipe_refusals = growth_refusals = auth_calls = 0;
    reads                                                = 0;
    auth_available = auth_match = true;
    fallbackFinishResetScheduledTask();
    twfWorkerEnvSetupWithBufferSizes(&f.env, pool, 512, 320, 8192, pool);
    f.metadata           = nodeVlessServerGet();
    f.metadata.hash_next = 1;
    f.metadata.next      = (char *) "next";
    f.metadata.node_settings_json =
        cJSON_Parse("{\"users\":[{\"username\":\"alice\",\"uuid\":\"42424242-4242-4242-4242-424242424242\"}]}");
    f.t = vlessserverTunnelCreate(&f.metadata);
    twfRequire(f.t != NULL, "server construction failed");
    f.prev     = twfCreatePrevTunnel(&f.trace);
    f.next     = twfCreateNextTunnel(&f.trace);
    f.fallback = twfCreateNextTunnel(&f.trace);
    tunnelBind(f.prev, f.t);
    tunnelBind(f.t, f.next);
    f.prev->fnPayloadD = f.next->fnPayloadU = f.fallback->fnPayloadU = capture;
    f.prev->fnFinD                                                   = ownerFinish;
    f.next->fnInitU = f.fallback->fnInitU = onInit;
    f.next->fnFinU = f.fallback->fnFinU = branchFinish;
    f.prev->fnEstD                      = onEst;
    f.prev->fnPauseD = f.next->fnPauseU = f.fallback->fnPauseU = onPause;
    f.prev->fnResumeD = f.next->fnResumeU = f.fallback->fnResumeU = onResume;
    f.auto_est                                                    = true;
    f.database                                                    = database;
    vlessserver_tstate_t *ts                                      = tunnelGetState(f.t);
    ts->fallback_tunnel                                           = fallback ? f.fallback : NULL;
    ts->fallback_intentional_delay_ms = ts->fallback_intentional_delay_jitter_ms = 0;
    if (database)
        ts->auth_client_tunnel = f.next;
    twfLinePoolSetup(&f.lines, f.t->lstate_size, 8);
    f.chain                  = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(void *));
    f.chain->line_pools[0]   = f.lines.pools[0];
    f.chain->supports_splice = WW_HAVE_SPLICE;
    f.t->chain               = f.chain;
    f.line                   = twfLinePoolCreateLine(&f.lines);
    lineRef(f.line);
    f.t->fnInitU(f.t, f.line);
}
static void end(void)
{
    f.action = 0;
    if (lineIsAlive(f.line))
    {
        f.t->fnFinU(f.t, f.line);
        lineDestroy(f.line);
    }
    if (g_fallback_finish_task.pending)
        fallbackFinishDriveDelayedTask();
    twfRequireLineStateZeroed(f.line, f.t, "client state survived close");
    twfRequire(twfLineRefCount(f.line) == 1, "association leaked a reference");
    lineUnref(f.line);
    for (unsigned i = 0; i < f.remote_count; ++i)
    {
        twfRequire(! lineIsAlive(f.remotes[i]), "owned backend survived close");
        twfRequireLineStateZeroed(f.remotes[i], f.t, "backend state survived close");
        twfRequire(twfLineRefCount(f.remotes[i]) == 1, "backend reference leaked");
        lineUnref(f.remotes[i]);
    }
    twfLinePoolTeardown(&f.lines);
    f.t->onDestroy(f.t, wwLifecycleStartupRollback());
    tunnelDestroy(f.prev);
    tunnelDestroy(f.next);
    tunnelDestroy(f.fallback);
    cJSON_Delete(f.metadata.node_settings_json);
    memoryFree(f.metadata.type);
    memoryFree(f.chain);
    twfWorkerEnvTeardown(&f.env);
}
static void startUdp(void)
{
    uint8_t  wire[320];
    uint32_t n = request(wire, 0, true);
    f.t->fnPayloadU(f.t, f.line, bytes(wire, n, true, 320));
}
static void datagram(uint16_t port, const void *data, uint32_t n, bool pipe)
{
    uint8_t  wire[9000];
    discard  port;
    uint32_t len = frame(wire, data, n);
    f.t->fnPayloadU(f.t, f.line, bytes(wire, len, pipe && len <= 4096, 320));
}

static void testRequests(void)
{
    twfSetCase("initial request splits, auth caching, exact header consumption and TCP identity");
    uint8_t wire[1024];
    for (unsigned form = 0; form < 4; ++form)
    {
        uint32_t n = request(wire, form, false);
        memoryCopy(wire + n, "AB", 2);
        for (unsigned split = 17; split <= n + 2; ++split)
        {
            begin(false, true, 128);
            f.t->fnPayloadU(f.t, f.line, bytes(wire, split, true, 320));
            if (split != n + 2)
                f.t->fnPayloadU(f.t, f.line, bytes(wire + split, n + 2 - split, true, 320));
            twfRequire(f.inits == 1 && f.ests == 1 && auth_calls == 1, "request repeated authentication or Init/Est");
            twfRequire(f.up_len == 2 && memcmp(f.up, "AB", 2) == 0, "TCP request consumed body");
            twfRequire(f.parser_reads == (WW_HAVE_SPLICE ? n : 0), "TCP parser read body bytes");
            for (unsigned dir = 0; dir < 2; ++dir)
            {
                sbuf_t *b = bytes("opaque", 6, true, 320);
                if (dir)
                    f.t->fnPayloadU(f.t, f.line, b);
                else
                    f.t->fnPayloadD(f.t, f.line, b);
                twfRequire(f.last == b, "established TCP buffer replaced");
            }
            end();
        }
    }
    begin(false, false, 128);
    uint32_t n = request(wire, 0, false);
    sbuf_t  *b = bytes("AB", 2, true, 320);
    sbufShiftLeft(b, n);
    sbufWrite(b, wire, n);
    f.t->fnPayloadU(f.t, f.line, b);
    twfRequire(f.parser_reads == 0 && memcmp(f.up, "AB", 2) == 0, "resident request header read a pipe body");
    end();
    begin(false, false, 128);
    uint8_t *large = memoryAllocate(1024 * 1024 + 320);
    n              = request(large, 3, false);
    memset(large + n, 'L', 1024 * 1024);
    f.t->fnPayloadU(f.t, f.line, bytes(large, 17, true, 320));
    f.t->fnPayloadU(f.t, f.line, bytes(large + 17, n + 1024 * 1024 - 17, false, 320));
    twfRequire(f.up_len == 1024 * 1024 && f.up[0] == 'L' && f.up[f.up_len - 1] == 'L', "coalesced 1 MiB body rejected");
    memoryFree(large);
    end();
}
static void testFallback(void)
{
    twfSetCase("mixed delayed fallback replay, pressure, task rejection and teardown");
    for (unsigned fault = 0; fault < 4; ++fault)
    {
        begin(true, false, 128);
        vlessserver_tstate_t *ts                 = tunnelGetState(f.t);
        ts->fallback_intentional_delay_ms        = 7;
        ts->fallback_intentional_delay_jitter_ms = 1;
        uint8_t probe[2048];
        memset(probe, 'x', sizeof(probe));
        f.t->fnPayloadU(f.t, f.line, bytes(probe, sizeof(probe), true, 320));
        f.t->fnPayloadU(f.t, f.line, bytes(probe, sizeof(probe), true, 320));
        f.t->fnPayloadU(f.t, f.line, bytes(probe, sizeof(probe), false, 320));
        twfRequire(f.fallback_inits == 1 && f.calls_fallback == 0 && g_fallback_finish_task.pending,
                   "fallback delay not retained");
        twfRequire(g_fallback_finish_task.delay_ms >= 6 && g_fallback_finish_task.delay_ms <= 8,
                   "fallback jitter changed");
        fail_pipe     = fault == 1;
        pressure      = fault == 2;
        reject_growth = fault == 3;
        fallbackFinishDriveDelayedTask();
        twfRequire(f.calls_fallback == 1 && f.replay_len == 6144, "fallback batch not delivered once");
        for (size_t i = 0; i < f.replay_len; ++i)
            twfRequire(f.replay[i] == 'x', "fallback replay corrupted");
        end();
    }
    begin(true, false, 128);
    ((vlessserver_tstate_t *) tunnelGetState(f.t))->fallback_intentional_delay_ms = 7;
    g_fallback_finish_task.refuse                                                 = true;
    f.t->fnPayloadU(f.t, f.line, bytes("probe", 5, true, 320));
    twfRequire(! lineIsAlive(f.line), "task refusal did not close fallback");
    end();
}

static bool local_reply_pipe;
static void localFallbackReplyAndFinish(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    capture(t, l, buf);
    f.t->fnPayloadD(f.t, l, bytes("response", 8, local_reply_pipe, 320));
    if (lineIsAlive(l))
        f.t->fnFinD(f.t, l);
}

static void testFallbackLocalReplies(void)
{
    twfSetCase("fallback local reply precedes Finish without requiring Est or an idle upstream pump");
    for (unsigned pipe = 0; pipe < 2; ++pipe)
    {
        for (unsigned delayed = 0; delayed < 2; ++delayed)
        {
            for (unsigned established = 0; established < 2; ++established)
            {
                begin(true, false, 128);
                f.auto_est             = established != 0;
                local_reply_pipe       = pipe != 0;
                f.fallback->fnPayloadU = localFallbackReplyAndFinish;
                ((vlessserver_tstate_t *) tunnelGetState(f.t))->fallback_intentional_delay_ms = delayed ? 7 : 0;
                f.t->fnPayloadU(f.t, f.line, bytes("probe", 5, pipe != 0, 320));
                if (delayed)
                    fallbackFinishDriveDelayedTask();
                twfRequire(f.down_len == 8 && memcmp(f.down, "response", 8) == 0,
                           "fallback response was discarded by immediate Finish");
                twfRequire(! lineIsAlive(f.line) && f.finishes == 1 && f.branch_finishes == 0,
                           "fallback Finish leaked or reflected");
                end();
            }
        }
    }

    twfSetCase("fallback admitted replies preserve reentry order before Est and through Pause");
    for (unsigned action = 3; action <= 6; ++action)
    {
        if (action == 5)
            continue;
        begin(true, false, 128);
        f.auto_est = false;
        f.t->fnPayloadU(f.t, f.line, bytes("probe", 5, true, 320));
        f.down_paused = true;
        f.t->fnPauseU(f.t, f.line);
        f.boundary = 4;
        f.action   = action;
        f.t->fnPayloadD(f.t, f.line, bytes("A", 1, true, 320));
        f.t->fnPayloadD(f.t, f.line, bytes("B", 1, false, 320));
        twfRequire(f.ests == 0 && f.down_len == (action == 6 ? 3U : 2U) &&
                       memcmp(f.down, action == 6 ? "AZB" : "AB", f.down_len) == 0,
                   "fallback admitted replies stalled or reordered");
        end();
    }

    twfSetCase("fallback local reply survives reentrant source close without a reflected Finish");
    begin(true, false, 128);
    f.auto_est             = false;
    local_reply_pipe       = true;
    f.fallback->fnPayloadU = localFallbackReplyAndFinish;
    f.boundary             = 4;
    f.action               = 7;
    f.t->fnPayloadU(f.t, f.line, bytes("probe", 5, true, 320));
    twfRequire(f.down_len == 8 && ! lineIsAlive(f.line) && f.branch_finishes == 1 && f.finishes == 0,
               "source close during fallback reply was not settled once");
    end();
}
static void testAuthentication(void)
{
    twfSetCase("first callback credentials and authenticated rejection");
    uint8_t wire[512];
    for (unsigned length = 0; length < 17; ++length)
    {
        begin(true, false, 128);
        request(wire, 0, false);
        f.t->fnPayloadU(f.t, f.line, bytes(wire, length, true, 320));
        twfRequire(f.fallback_inits == 1 && f.replay_len == length && ! memcmp(f.replay, wire, length),
                   "short first credential replay changed");
        end();
    }
    for (unsigned fault = 0; fault < 9; ++fault)
    {
        begin(true, fault != 1, 128);
        uint32_t n = request(wire, 0, false);
        if (fault == 0)
            wire[0] = 1;
        if (fault == 1)
            wire[1] ^= 1;
        if (fault == 2)
            auth_match = false;
        if (fault == 3)
            auth_available = false;
        if (fault == 4)
            wire[17] = 1;
        if (fault == 5)
            wire[18] = 7;
        if (fault == 6)
            wire[21] = 7;
        if (fault == 7)
            wire[19] = wire[20] = 0;
        if (fault == 8)
        {
            wire[21] = 2;
            wire[22] = 0;
        }
        f.t->fnPayloadU(f.t, f.line, bytes(wire, n, true, 320));
        if (fault < 4)
            twfRequire(f.fallback_inits == 1 && f.replay_len == n && ! memcmp(f.replay, wire, n) && f.down_len == 0,
                       "unauthenticated replay lost inspected bytes");
        else
            twfRequire(! lineIsAlive(f.line) && f.fallback_inits == 0, "authenticated malformed input fell back");
        end();
    }
    begin(false, true, 128);
    uint32_t n = request(wire, 0, false);
    sbuf_t  *b = bytes(wire + 8, 9, true, 320);
    sbufShiftLeft(b, 8);
    sbufWrite(b, wire, 8);
    f.t->fnPayloadU(f.t, f.line, b);
    twfRequire(auth_calls == 1 && f.inits == 0, "mixed 17-byte credential was not authenticated");
    f.t->fnPayloadU(f.t, f.line, bytes(wire + 17, n - 17, true, 320));
    twfRequire(auth_calls == 1 && f.inits == 1, "cached authentication repeated");
    end();
    begin(true, true, 128);
    request(wire, 0, false);
    wire[17] = 255;
    f.t->fnPayloadU(f.t, f.line, bytes(wire, 18, true, 320));
    twfRequire(lineIsAlive(f.line), "incomplete addons rejected early");
    memset(wire, 0, 255);
    f.t->fnPayloadU(f.t, f.line, bytes(wire, 255, true, 320));
    twfRequire(! lineIsAlive(f.line) && f.fallback_inits == 0, "unsupported addons accepted");
    end();
}

static void testUdp(void)
{
    twfSetCase("fixed UDP target, exact extraction, fragments and reply framing");
    uint8_t *wire = memoryAllocate(65540), *body = memoryAllocate(65536);
    memset(body, 'P', 65536);
    for (unsigned split = 1; split < 6; ++split)
    {
        begin(false, false, 128);
        startUdp();
        uint32_t n = frame(wire, "ABCD", 4);
        f.t->fnPayloadU(f.t, f.line, bytes(wire, split, true, 320));
        twfRequire(f.calls_up == 0, "incomplete UDP emitted");
        f.t->fnPayloadU(f.t, f.line, bytes(wire + split, n - split, true, 320));
        twfRequire(f.calls_up == 1 && f.up_len == 4 && ! memcmp(f.up, "ABCD", 4) && f.ports[0] == 443,
                   "UDP frame or fixed target changed");
        twfRequire(f.headroom >= bufferpoolGetLargeBufferPadding(f.env.pool), "UDP lost onward padding");
        end();
    }
    for (unsigned n = 1; n <= 65535; n = n == 1 ? 1500 : n == 1500 ? 65535 : 65536)
    {
        begin(false, false, 128);
        startUdp();
        uint32_t total = frame(wire, body, n);
        for (unsigned off = 0; off < total;)
        {
            unsigned count = min(n == 1500 ? 1U : 2048U, total - off);
            f.t->fnPayloadU(f.t, f.line, bytes(wire + off, count, n != 1500, 320));
            off += count;
        }
        twfRequire(f.calls_up == 1 && f.up_len == n && ! memcmp(f.up, body, n), "UDP fragment or maximum body lost");
        end();
    }
    begin(false, false, 128);
    startUdp();
    uint32_t n = frame(wire, "A", 1);
    n += frame(wire + n, "B", 1);
    wire[n++]  = 0;
    f.boundary = 3;
    f.action   = 1;
    f.t->fnPayloadU(f.t, f.line, bytes(wire, n, true, 320));
    twfRequire(f.calls_up == 2 && ! memcmp(f.up, "AB", 2), "Pause stopped accepted UDP batch");
    const uint8_t suffix[] = {1, 'C'};
    f.t->fnPayloadU(f.t, f.line, bytes(suffix, 2, true, 320));
    twfRequire(f.calls_up == 3 && f.up[2] == 'C', "UDP incomplete suffix lost");
    for (unsigned pad = 0; pad <= 320; pad += 320)
    {
        f.t->fnPayloadD(f.t, f.remotes[0], bytes("reply", 5, true, pad));
        twfRequire(! memcmp(f.down + f.down_len - 7, "\0\5reply", 7), "UDP reply prepend corrupted pipe");
    }
    size_t before = f.down_len;
    f.t->fnPayloadD(f.t, f.remotes[0], bytes(body, 0, false, 0));
    f.t->fnPayloadD(f.t, f.remotes[0], bytes(body, 65536, false, 0));
    twfRequire(f.down_len == before && lineIsAlive(f.remotes[0]), "invalid local replies changed drop policy");
    f.t->fnPayloadD(f.t, f.remotes[0], bytes(body, 65535, false, 0));
    twfRequire(f.down_len == before + 65537, "maximum reply rejected");
    f.t->fnFinD(f.t, f.remotes[0]);
    datagram(443, "D", 1, true);
    twfRequire(f.remote_count == 2 && f.ests == 1 && f.up[3] == 'D', "backend replacement lost Est latch or data");
    f.t->fnPayloadU(f.t, f.line, bytes("\0\0", 2, true, 320));
    twfRequire(! lineIsAlive(f.line), "zero-length received datagram accepted");
    end();
    memoryFree(wire);
    memoryFree(body);
}

static void testReentry(void)
{
    twfSetCase("Init, Est, payload reentry and exact-line close");
    uint8_t wire[512];
    for (unsigned fallback = 0; fallback < 2; ++fallback)
        for (unsigned boundary = 1; boundary <= 3; ++boundary)
        {
            begin(fallback, false, 128);
            unsigned n = request(wire, 0, false);
            wire[n++]  = 'A';
            if (fallback)
                wire[0] = 1;
            f.boundary = boundary;
            f.action   = 5;
            f.t->fnPayloadU(f.t, f.line, bytes(wire, n, true, 320));
            if (g_fallback_finish_task.pending)
                fallbackFinishDriveDelayedTask();
            twfRequire(fallback ? f.replay_len == n + 1 && f.replay[n] == 'C'
                                : f.up_len == 2 && ! memcmp(f.up, "AC", 2),
                       "nested input overtook original");
            end();
        }
    for (unsigned udp = 0; udp < 2; ++udp)
        for (unsigned boundary = 1; boundary <= 5; ++boundary)
        {
            begin(false, false, 128);
            f.boundary = boundary;
            f.action   = 7;
            unsigned n = request(wire, 0, udp);
            if (udp)
                n += frame(wire + n, "A", 1);
            else
                wire[n++] = 'A';
            if (boundary == 5)
                f.t->fnPauseU(f.t, f.line);
            f.t->fnPayloadU(f.t, f.line, bytes(wire, n, true, 320));
            twfRequire(! lineIsAlive(f.line), "callback close left client alive");
            end();
        }
    begin(true, false, 128);
    ((vlessserver_tstate_t *) tunnelGetState(f.t))->fallback_intentional_delay_ms = 7;
    f.boundary                                                                    = 1;
    f.action                                                                      = 7;
    f.t->fnPayloadU(f.t, f.line, bytes("probe", 5, true, 320));
    twfRequire(! lineIsAlive(f.line) && f.calls_fallback == 0, "source Finish flushed during branch Init");
    end();
}

static bool fallback_reply_paused;

static void fallbackReplyPause(tunnel_t *t, line_t *l)
{
    fallback_reply_paused = true;
    onPause(t, l);
}

static void fallbackReplyResume(tunnel_t *t, line_t *l)
{
    fallback_reply_paused = false;
    onResume(t, l);
}

static void testFallbackReceiverPressure(void)
{
    twfSetCase("fallback preserves current receiver pressure across Init");
    const unsigned actions[] = {0, 3, 4}; /* None, Pause, Pause then Resume during Init. */
    for (unsigned paused = 0; paused < 2; ++paused)
        for (unsigned i = 0; i < sizeof(actions) / sizeof(actions[0]); ++i)
        {
            begin(true, false, 128);
            fallback_reply_paused = false;
            f.fallback->fnPauseU  = fallbackReplyPause;
            f.fallback->fnResumeU = fallbackReplyResume;
            if (paused)
                f.t->fnPauseU(f.t, f.line);
            twfRequire(f.pauses == 0, "receiver Pause escaped before fallback Init");
            f.boundary = 1;
            f.action   = actions[i];
            f.t->fnPayloadU(f.t, f.line, bytes("probe", 5, true, 320));
            bool expected = actions[i] == 3 || (actions[i] == 0 && paused);
            twfRequire(fallback_reply_paused == expected,
                       "fallback backend received stale or missing receiver pressure after Init");
            twfRequire(((vlessserver_lstate_t *) lineGetState(f.line, f.t))->response_paused == expected,
                       "fallback receiver pressure state did not follow nested callbacks");
            if (actions[i] == 4)
                twfRequire(f.pauses == 1 && f.resumes == 1, "fallback replayed Pause after nested Resume");
            if (expected)
            {
                f.t->fnResumeU(f.t, f.line);
                twfRequire(! fallback_reply_paused, "fallback did not release receiver pressure");
            }
            end();
        }

    for (unsigned action = 7; action <= 8; ++action)
    {
        begin(true, false, 128);
        f.t->fnPauseU(f.t, f.line);
        f.boundary = 5;
        f.action   = action; /* Close from either side during the replayed Pause. */
        f.t->fnPayloadU(f.t, f.line, bytes("probe", 5, true, 320));
        /* Source Finish may flush one final admitted batch outside Init;
         * backend Finish must receive neither replay nor reflected Finish. */
        unsigned final_batch = action == 7 ? 1 : 0;
        twfRequire(! lineIsAlive(f.line) && f.calls_fallback == final_batch && f.branch_finishes == final_batch,
                   "fallback did not settle receiver-Pause closure exactly once");
        end();
    }
}

static void testLimits(void)
{
    twfSetCase("transactional byte/entry budgets and parser settlement");
    uint8_t *data = memoryAllocateZero(kVlessServerMaxBufferedBytes + 512);
    for (unsigned direction = 0; direction < 2; ++direction)
        for (unsigned entries = 0; entries < 2; ++entries)
        {
            begin(direction == 0, false, 128);
            vlessserver_lstate_t *ls = lineGetState(f.line, f.t);
            if (direction == 0)
            {
                f.t->fnPayloadU(f.t, f.line, bytes("", 0, false, 320));
                ls->input_dispatching = true;
            }
            else
            {
                unsigned n = request(data, 0, false);
                f.t->fnPayloadU(f.t, f.line, bytes(data, n, false, 320));
                ls->response_dispatching = true;
            }
            for (unsigned i = 0; i < (entries ? 1024 : 1); ++i)
            {
                sbuf_t *b = bytes(data, entries ? 0 : kVlessServerMaxPendingBytes, false, 320);
                if (direction)
                    f.t->fnPayloadD(f.t, f.line, b);
                else
                    f.t->fnPayloadU(f.t, f.line, b);
            }
            buffer_budget_t *budget = direction ? &ls->response_budget : &ls->upstream_budget;
            twfRequire(lineIsAlive(f.line) && bufferbudgetGetUsage(budget).entries == (entries ? 1024 : 1),
                       "exact budget rejected or accounting lost");
            sbuf_t *extra = bytes(data, entries ? 0 : 1, false, 320);
            if (direction)
                f.t->fnPayloadD(f.t, f.line, extra);
            else
                f.t->fnPayloadU(f.t, f.line, extra);
            twfRequire(! lineIsAlive(f.line), "output budget overflow accepted");
            end();
        }
    begin(false, false, 128);
    startUdp();
    vlessserver_lstate_t *ls = lineGetState(f.line, f.t);
    ls->input_dispatching    = true;
    f.t->fnPayloadU(f.t, f.line, bytes(data, kVlessServerMaxBufferedBytes, false, 320));
    twfRequire(lineIsAlive(f.line) && ls->input_bytes == kVlessServerMaxBufferedBytes, "parser equality rejected");
    f.t->fnPayloadU(f.t, f.line, bytes(data, 1, false, 320));
    twfRequire(! lineIsAlive(f.line), "parser overflow accepted");
    end();
    begin(false, false, 128);
    unsigned n = request(data, 0, false);
    f.t->fnPayloadU(f.t, f.line, bytes(data, 17, true, 320));
    ls = lineGetState(f.line, f.t);
    twfRequire(ls->input_bytes == 17 && ls->header_filled == 17, "cached metadata charge lost");
    fail_queue = true;
    f.t->fnPayloadU(f.t, f.line, bytes(data + 17, n - 17, true, 320));
    twfRequire(! lineIsAlive(f.line), "queue refusal did not settle partial parser");
    end();
    /* The older body remains charged across branch Init. */
    for (unsigned entries = 0; entries < 2; ++entries)
    {
        begin(false, false, 128);
        n                    = request(data, 0, false);
        data[n++]            = 'A';
        f.boundary           = 1;
        f.action             = 12;
        f.admission_entries  = entries ? 1023 : 1;
        f.admission_bytes    = entries ? 0 : kVlessServerMaxPendingBytes - 1;
        f.overflow_admission = true;
        f.t->fnPayloadU(f.t, f.line, bytes(data, n, true, 320));
        twfRequire(! lineIsAlive(f.line), "older body not included in shared budget");
        end();
    }
    memoryFree(data);
}

static void testRepresentationsAndPipePressure(void)
{
    twfSetCase("prefix-only requests, opaque large pipe bodies and complete helper fallback");
    uint8_t wire[8192], body[6000];
    memset(body, 'Q', sizeof(body));
    begin(false, false, 128);
    unsigned n = request(wire, 3, false);
    sbuf_t  *b = bytes("", 0, true, 320);
    sbufShiftLeft(b, n);
    sbufWrite(b, wire, n);
    f.t->fnPayloadU(f.t, f.line, b);
    twfRequire(f.inits == 1 && f.parser_reads == 0, "prefix-only request accessed pipe metadata");
    end();
    begin(false, false, 128);
    n = request(wire, 0, false);
    memcpy(wire + n, body, 2048);
    b = bytes(wire, n + 2048, true, 320);
    f.t->fnPayloadU(f.t, f.line, b);
    twfRequire(f.up_len == 2048 && ! memcmp(f.up, body, 2048) && f.parser_reads == (WW_HAVE_SPLICE ? n : 0),
               "large TCP body was read by parser");
#if WW_HAVE_SPLICE
    twfRequire(f.last == b && f.last_splice, "transferable pipe body replaced");
#endif
    end();
    for (unsigned fault = 0; fault < 3; ++fault)
    {
        begin(false, false, 128);
        startUdp();
        n = frame(wire, body, sizeof(body));
        f.t->fnPayloadU(f.t, f.line, bytes(wire, 3000, true, 320));
        b             = bytes(wire + 3000, n - 3000, true, 320);
        fail_pipe     = fault == 0;
        pressure      = fault == 1;
        reject_growth = fault == 2;
        f.t->fnPayloadU(f.t, f.line, b);
        twfRequire(f.up_len == sizeof(body) && ! memcmp(f.up, body, sizeof(body)), "UDP helper fallback lost bytes");
#if WW_HAVE_SPLICE
        twfRequire(! f.last_splice, "pipe refusal/pressure did not select ordinary fallback");
        if (fault == 0)
            twfRequire(pipe_refusals != 0, "pipe creation refusal not exercised");
        if (fault == 1)
            twfRequire(moves >= 2, "positive-short then pressure not exercised");
        if (fault == 2)
            twfRequire(growth_refusals != 0, "small-pipe exhaustion not exercised");
#endif
        end();
    }
    begin(true, false, 128);
    ((vlessserver_tstate_t *) tunnelGetState(f.t))->fallback_intentional_delay_ms = 7;
    f.t->fnPayloadU(f.t, f.line, bytes("probe", 5, true, 320));
    f.t->fnPauseD(f.t, f.line);
    fallbackFinishDriveDelayedTask();
    twfRequire(f.calls_fallback == 0, "delayed splice replay bypassed Pause");
    f.t->fnResumeD(f.t, f.line);
    fallbackFinishDriveDelayedTask();
    twfRequire(f.replay_len == 5 && ! memcmp(f.replay, "probe", 5), "Resume lost delayed splice replay");
    end();
    begin(true, false, 128);
    ((vlessserver_tstate_t *) tunnelGetState(f.t))->fallback_intentional_delay_ms = 7;
    f.t->fnPayloadU(f.t, f.line, bytes("probe", 5, true, 320));
    f.t->fnPauseD(f.t, f.line);
    end();
    twfRequire(f.calls_fallback == 0, "source Finish bypassed paused pipe backlog");
}

int main(void)
{
    twfRequire(wCryptoGlobalInit() == kWCryptoOk, "crypto init failed");
    twfRequire(globalstateInitializeSecureRandom(), "secure random initialization failed");
    twfRequire(frandGlobalInit(), "random initialization failed");
    testFallbackReceiverPressure();
    testRepresentationsAndPipePressure();
    testRequests();
    testAuthentication();
    testUdp();
    testReentry();
    testFallback();
    testFallbackLocalReplies();
    testLimits();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    puts("vlessserver splice tests passed");
    return 0;
}
