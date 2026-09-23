#include "AuthenticationClient/interface.h"
#include "TrojanServer/interface.h"
#include "TrojanServer/structure.h"
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

static bool fail_map;
void       *__real_memoryAllocate(size_t);
void       *__wrap_memoryAllocate(size_t);
void       *__wrap_memoryAllocate(size_t size)
{
    if (fail_map && size == 8 * sizeof(trojanserver_remote_map_t_value))
    {
        fail_map = false;
        return NULL;
    }
    return __real_memoryAllocate(size);
}
static unsigned              auth_calls;
static bool                  auth_available = true, auth_match = true;
authenticationclient_state_t __wrap_authenticationclientGetState(tunnel_t *t);
authenticationclient_state_t __wrap_authenticationclientGetState(tunnel_t *t)
{
    discard t;
    return auth_available ? kAuthenticationClientStateReady : kAuthenticationClientStateStopped;
}
bool __wrap_authenticationclientGetUserBySHA224WithProfile(tunnel_t *t, const uint8_t *hash, user_handle_t *handle,
                                                           authenticationclient_user_profile_t *profile);
bool __wrap_authenticationclientGetUserBySHA224WithProfile(tunnel_t *t, const uint8_t *hash, user_handle_t *handle,
                                                           authenticationclient_user_profile_t *profile)
{
    discard t;
    discard hash;
    ++auth_calls;
    if (! auth_match)
        return false;
    userHandleSet(handle, 1, 42);
    profile->name     = stringDuplicate("alice");
    profile->password = stringDuplicate("test");
    return true;
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
static fixture_t f;
static uint8_t   hash_hex[56];
static sbuf_t   *bytes(const void *data, uint32_t n, bool pipe, uint16_t padding)
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
static uint32_t address(uint8_t *out, unsigned form, uint16_t port)
{
    uint32_t n;
    if (form == 0)
    {
        out[0] = 1;
        out[1] = 127;
        out[2] = out[3] = 0;
        out[4]          = 1;
        n               = 5;
    }
    else if (form == 1)
    {
        out[0] = 4;
        memset(out + 1, 0, 16);
        out[16] = 1;
        n       = 17;
    }
    else
    {
        out[0] = 3;
        out[1] = form == 2 ? 1 : 255;
        memset(out + 2, 'a', out[1]);
        n = 2 + out[1];
    }
    out[n++] = (uint8_t) (port >> 8);
    out[n++] = (uint8_t) port;
    return n;
}
static uint32_t request(uint8_t *out, unsigned form, bool udp)
{
    memoryCopy(out, hash_hex, 56);
    out[56]    = '\r';
    out[57]    = '\n';
    out[58]    = udp ? 3 : 1;
    uint32_t n = 59 + address(out + 59, form, udp ? 0 : 443);
    out[n++]   = '\r';
    out[n++]   = '\n';
    return n;
}
static uint32_t frame(uint8_t *out, unsigned form, uint16_t port, const void *body, uint32_t len)
{
    uint32_t n = address(out, form, port);
    out[n++]   = (uint8_t) (len >> 8);
    out[n++]   = (uint8_t) len;
    out[n++]   = '\r';
    out[n++]   = '\n';
    if (body != NULL && len != 0)
        memoryCopy(out + n, body, len);
    return n + len;
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
    if (t != f.prev)
        twfRequire(l != f.line || ! ((trojanserver_lstate_t *) lineGetState(l, f.t))->paused_remotes,
                   "UDP Pause used uninitialized client next state");
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
        twfRequire(lineHasAuthenticatedCredentials(l, "alice", "test"), "protected branch lost credentials");
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
    if (lineIsAlive(l) && ((trojanserver_lstate_t *) lineGetState(l, f.t))->phase != kTrojanServerPhaseClosing &&
        f.auto_est)
        f.t->fnEstD(f.t, l);
}
static void begin(bool fallback, bool database, uint32_t pool)
{
    memoryZero(&f, sizeof(f));
    fail_queue = fail_pipe = pressure = reject_growth = fail_map = false;
    moves = pipe_refusals = growth_refusals = auth_calls = 0;
    reads                                                = 0;
    auth_available = auth_match = true;
    fallbackFinishResetScheduledTask();
    twfWorkerEnvSetupWithBufferSizes(&f.env, pool, 512, 320, 8192, pool);
    f.metadata                    = nodeTrojanServerGet();
    f.metadata.hash_next          = 1;
    f.metadata.next               = (char *) "next";
    f.metadata.node_settings_json = cJSON_Parse("{\"users\":[{\"username\":\"alice\",\"password\":\"test\"}]}");
    f.t                           = trojanserverTunnelCreate(&f.metadata);
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
    trojanserver_tstate_t *ts                                     = tunnelGetState(f.t);
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
    uint32_t len = frame(wire, 0, port, data, n);
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
        for (unsigned split = 56; split <= n + 2; ++split)
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
    f.t->fnPayloadU(f.t, f.line, bytes(large, 56, true, 320));
    f.t->fnPayloadU(f.t, f.line, bytes(large + 56, n + 1024 * 1024 - 56, false, 320));
    twfRequire(f.up_len == 1024 * 1024 && f.up[0] == 'L' && f.up[f.up_len - 1] == 'L', "coalesced 1 MiB body rejected");
    memoryFree(large);
    end();
}
static void testAuthentication(void)
{
    twfSetCase("fallback replay and pre/post-authentication rejection boundary");
    uint8_t  wire[400];
    uint32_t n = request(wire, 0, false);
    for (unsigned length = 0; length < 56; ++length)
    {
        begin(true, false, 128);
        f.t->fnPayloadU(f.t, f.line, bytes(wire, length, true, 320));
        twfRequire(f.fallback_inits == 1 && f.inits == 0 && f.replay_len == length &&
                       memcmp(f.replay, wire, length) == 0,
                   "segmented credential did not replay exact probe");
        end();
    }
    for (unsigned fault = 0; fault < 9; ++fault)
    {
        begin(true, true, 128);
        n = request(wire, 0, false);
        if (fault == 0)
            wire[0] = 'z';
        if (fault == 1)
            wire[56] = 'x';
        if (fault == 2)
            auth_match = false;
        if (fault == 3)
            auth_available = false;
        if (fault == 4)
            wire[58] = 7;
        if (fault == 5)
            wire[59] = 7;
        if (fault == 6)
            wire[n - 1] = 'x';
        if (fault == 7)
        {
            wire[64] = 0;
            wire[65] = 0;
        }
        if (fault == 8)
            ((trojanserver_tstate_t *) tunnelGetState(f.t))->allow_connect = false;
        f.t->fnPayloadU(f.t, f.line, bytes(wire, n, true, 320));
        if (fault < 4)
            twfRequire(f.fallback_inits == 1 && f.replay_len == n && memcmp(f.replay, wire, n) == 0,
                       "unauthenticated replay lost bytes");
        else
            twfRequire(! lineIsAlive(f.line) && f.fallback_inits == 0, "authenticated malformed request fell back");
        end();
    }
    begin(true, true, 128);
    n = request(wire, 0, false);
    f.t->fnPayloadU(f.t, f.line, bytes(wire, 56, true, 320));
    twfRequire(auth_calls == 1 && f.inits == 0, "exact hash was not authenticated once");
    f.t->fnPayloadU(f.t, f.line, bytes("x", 1, true, 320));
    twfRequire(! lineIsAlive(f.line) && f.fallback_inits == 0, "late bad CRLF fell back after authentication");
    end();
}
static void testReentrancy(void)
{
    twfSetCase("TCP/fallback Init and Est barriers, producer permission and callback death");
    uint8_t wire[400];
    for (unsigned fallback = 0; fallback < 2; ++fallback)
    {
        for (unsigned boundary = 1; boundary <= 2; ++boundary)
        {
            begin(fallback, false, 128);
            uint32_t n = fallback ? 56 : request(wire, 0, false);
            if (fallback)
                memset(wire, 'x', n);
            else
                wire[n++] = 'A';
            f.boundary = boundary;
            f.action   = 5;
            f.t->fnPayloadU(f.t, f.line, bytes(wire, n, true, 320));
            if (g_fallback_finish_task.pending)
                fallbackFinishDriveDelayedTask();
            if (fallback)
                twfRequire(f.replay_len == 57 && f.replay[56] == 'C', "fallback Init/Est input overtook replay");
            else
                twfRequire(f.up_len == 2 && memcmp(f.up, "AC", 2) == 0, "TCP Init/Est input overtook body");
            end();
        }
        for (unsigned boundary = 1; boundary <= 6; ++boundary)
        {
            for (unsigned action = 7; action <= 8; ++action)
            {
                begin(fallback, false, 128);
                uint32_t n = fallback ? 56 : request(wire, 0, false);
                if (fallback)
                    memset(wire, 'x', n);
                else
                    wire[n++] = 'A';
                f.boundary = boundary;
                f.action   = action;
                f.t->fnPayloadU(f.t, f.line, bytes(wire, n, true, 320));
                if (boundary == 4)
                    f.t->fnPayloadD(f.t, f.line, bytes("reply", 5, true, 320));
                if (boundary >= 5)
                {
                    f.t->fnPauseD(f.t, f.line);
                    if (boundary == 6)
                        f.t->fnResumeD(f.t, f.line);
                }
                twfRequire(! lineIsAlive(f.line), "callback death left client alive");
                if (boundary == 1)
                    twfRequire(f.calls_up == 0 && f.calls_fallback == 0, "Init close submitted replay/body");
                end();
            }
        }
    }
    for (unsigned action = 1; action <= 4; ++action)
    {
        begin(false, false, 128);
        uint32_t n = request(wire, 0, false);
        wire[n++]  = 'A';
        f.boundary = 1;
        f.action   = action;
        f.t->fnPayloadU(f.t, f.line, bytes(wire, n, true, 320));
        f.t->fnPayloadU(f.t, f.line, bytes("B", 1, true, 320));
        f.t->fnPayloadD(f.t, f.line, bytes("R", 1, true, 320));
        if (action == 1)
            twfRequire(f.up_len == 2, "Init Pause stopped admitted TCP");
        if (action == 3)
            twfRequire(f.down_len == 1, "reply Pause stopped admitted TCP");
        f.down_paused = false;
        f.t->fnResumeU(f.t, f.line);
        f.t->fnResumeD(f.t, f.line);
        twfRequire(f.up_len == 2 && memcmp(f.up, "AB", 2) == 0 && f.down_len == 1, "Resume stranded TCP FIFO");
        end();
    }
}
static void testUdpFrames(void)
{
    twfSetCase("UDP destination headers, fragments, empty frames and exact body extraction");
    uint8_t wire[9000], payload[8192];
    memset(payload, 'P', sizeof(payload));
    for (unsigned form = 0; form < 4; ++form)
    {
        uint32_t n = frame(wire, form, 443, "AB", 2);
        for (unsigned split = 1; split < n; ++split)
        {
            begin(false, true, 128);
            startUdp();
            f.t->fnPayloadU(f.t, f.line, bytes(wire, split, true, 320));
            twfRequire(f.calls_up == 0, "partial UDP frame emitted");
            f.t->fnPayloadU(f.t, f.line, bytes(wire + split, n - split, true, 320));
            twfRequire(f.calls_up == 1 && f.up_len == 2 && memcmp(f.up, "AB", 2) == 0 && f.ports[0] == 443,
                       "UDP split lost destination or bytes");
            if (f.last_splice)
                twfRequire(f.parser_reads == 68 + n - 2, "UDP parser materialized private body");
            twfRequire(f.ests == 1, "backend Est did not map once to association");
            end();
        }
        for (unsigned size_case = 0; size_case < 3; ++size_case)
        {
            uint32_t size = size_case == 0 ? 0 : size_case == 1 ? 1 : 8192;
            begin(false, false, 128);
            startUdp();
            n = frame(wire, form, 443, payload, size);
            for (unsigned off = 0; off < n;)
            {
                unsigned count = min(2048U, n - off);
                f.t->fnPayloadU(f.t, f.line, bytes(wire + off, count, true, 320));
                off += count;
            }
            twfRequire(f.calls_up == 1 && f.up_len == size && memcmp(f.up, payload, size) == 0,
                       "UDP size or boundary changed");
            end();
        }
    }
    begin(false, false, 128);
    startUdp();
    uint32_t n = frame(wire, 0, 443, payload, 1500);
    for (unsigned i = 0; i < n; ++i)
        f.t->fnPayloadU(f.t, f.line, bytes(wire + i, 1, false, 320));
    twfRequire(f.calls_up == 1 && f.up_len == 1500, "input fragment count incorrectly limited");
    end();
    for (unsigned fault = 0; fault < 5; ++fault)
    {
        begin(true, false, 128);
        startUdp();
        n = frame(wire, 0, 443, "A", 1);
        if (fault == 0)
            wire[0] = 7;
        if (fault == 1)
        {
            wire[0] = 3;
            wire[1] = 0;
        }
        if (fault == 2)
        {
            wire[5] = wire[6] = 0;
        }
        if (fault == 3)
            wire[10] = 'x';
        if (fault == 4)
        {
            wire[7] = 32;
            wire[8] = 1;
        }
        f.t->fnPayloadU(f.t, f.line, bytes(wire, n, true, 320));
        twfRequire(! lineIsAlive(f.line) && f.fallback_inits == 0, "malformed UDP survived or fell back");
        end();
    }
}
static void testUdpPressure(void)
{
    twfSetCase("association-wide backend Pause and ordered pre-Est replies");
    begin(false, false, 128);
    startUdp();
    datagram(1001, "A", 1, true);
    datagram(1002, "B", 1, true);
    f.t->fnPauseD(f.t, f.remotes[0]);
    f.t->fnPauseD(f.t, f.remotes[1]);
    f.t->fnPauseD(f.t, f.remotes[0]);
    datagram(1002, "C", 1, true);
    datagram(1001, "D", 1, true);
    twfRequire(f.calls_up == 4 && f.pauses == 1, "backend Pause stopped input or contributions repeated");
    f.t->fnResumeD(f.t, f.remotes[1]);
    f.t->fnResumeD(f.t, f.remotes[1]);
    twfRequire(f.calls_up == 4 && f.resumes == 0, "one Resume overrode another backend Pause");
    f.t->fnFinD(f.t, f.remotes[0]);
    twfRequire(f.calls_up == 4 && memcmp(f.up, "ABCD", 4) == 0 && f.resumes == 1,
               "closing paused backend stranded input");
    twfRequire(f.ports[2] == 1002 && f.ports[3] == 1001, "destination order changed");
    f.down_paused = true;
    f.t->fnPauseU(f.t, f.line);
    unsigned count = f.calls_down;
    f.t->fnPayloadD(f.t, f.remotes[1], bytes("R", 1, true, 0));
    f.boundary = 1;
    f.action   = 6;
    datagram(1003, "E", 1, true);
    twfRequire(f.calls_down == count + 2, "admitted backend replies waited for client Resume");
    for (unsigned i = 0; i < f.remote_count; ++i)
        if (lineIsAlive(f.remotes[i]))
            twfRequire(((trojanserver_lstate_t *) lineGetState(f.remotes[i], f.t))->next_pause_sent,
                       "new initialized backend missed client source Pause");
    f.down_paused = false;
    f.t->fnResumeU(f.t, f.line);
    twfRequire(f.calls_down == 2 && f.down[11] == 'R' && f.down[23] == 'Z', "shared reply FIFO reordered backends");
    end();
    for (unsigned close_first = 0; close_first < 2; ++close_first)
    {
        begin(false, false, 128);
        startUdp();
        f.auto_est = false;
        datagram(1001, "A", 1, true);
        datagram(1002, "B", 1, true);
        f.t->fnPayloadD(f.t, f.remotes[0], bytes("X", 1, true, 320));
        f.t->fnPayloadD(f.t, f.remotes[1], bytes("Y", 1, true, 320));
        f.t->fnEstD(f.t, f.remotes[1]);
        twfRequire(f.calls_down == 2 && f.down[11] == 'X' && f.ests == 1, "backend replies waited for Est");
        if (close_first)
            f.t->fnFinD(f.t, f.remotes[0]);
        else
            f.t->fnEstD(f.t, f.remotes[0]);
        twfRequire(f.calls_down == 2 && f.down[f.down_len - 1] == 'Y', "pre-Est close/Est stranded replies");
        end();
    }
    begin(false, false, 128);
    startUdp();
    f.boundary = 1;
    f.action   = 1;
    datagram(1001, "A", 1, true);
    twfRequire(f.calls_up == 1, "backend Init Pause stranded admitted datagram");
    f.t->fnResumeD(f.t, f.remotes[0]);
    twfRequire(f.calls_up == 1 && f.up[0] == 'A', "selected body lost on Resume");
    end();
}
static void testFallback(void)
{
    twfSetCase("mixed delayed fallback replay, pressure, task rejection and teardown");
    for (unsigned fault = 0; fault < 4; ++fault)
    {
        begin(true, false, 128);
        trojanserver_tstate_t *ts                = tunnelGetState(f.t);
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
    ((trojanserver_tstate_t *) tunnelGetState(f.t))->fallback_intentional_delay_ms = 7;
    g_fallback_finish_task.refuse                                                  = true;
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
                ((trojanserver_tstate_t *) tunnelGetState(f.t))->fallback_intentional_delay_ms = delayed ? 7 : 0;
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
static void testLimitsAndFailures(void)
{
    twfSetCase("fixed budgets, empty reply entries, queue/map refusal and large reply asymmetry");
    uint8_t *data = memoryAllocateZero(kTrojanServerMaxWireBytes + 320);
    for (unsigned pool = 0; pool < 2; ++pool)
    {
        for (unsigned entries = 0; entries < 2; ++entries)
        {
            begin(true, false, pool ? 131072 : 128);
            ((trojanserver_tstate_t *) tunnelGetState(f.t))->fallback_intentional_delay_ms = 7;
            f.t->fnPayloadU(f.t, f.line, bytes("", 0, false, 320));
            /* The empty first replay occupies one retained entry. */
            uint32_t count = entries ? 1023 : 1;
            for (uint32_t i = 0; i < count; ++i)
                f.t->fnPayloadU(f.t, f.line, bytes(data, entries ? 0 : kTrojanServerMaxPendingBytes, false, 320));
            twfRequire(lineIsAlive(f.line), "exact delayed backlog limit rejected");
            trojanserver_lstate_t *ls = lineGetState(f.line, f.t);
            twfRequire(ls->pending_up.budget == NULL && ls->fallback_pending_up->budget == &ls->output_budget &&
                           bufferbudgetGetUsage(&ls->output_budget).entries == count + 1 &&
                           bufferbudgetGetUsage(&ls->output_budget).bytes ==
                               (entries ? 0 : kTrojanServerMaxPendingBytes),
                       "fallback transition did not account the complete replay FIFO");
            f.t->fnPayloadU(f.t, f.line, bytes(data, entries ? 0 : 1, false, 320));
            twfRequire(! lineIsAlive(f.line), "delayed backlog overflow accepted");
            end();
        }
    }
    begin(false, false, 128);
    startUdp();
    datagram(1001, "A", 1, true);
    f.t->fnPayloadD(f.t, f.remotes[0], bytes(data, UINT16_MAX, false, 0));
    twfRequire(f.down_len == UINT16_MAX + 11 && lineIsAlive(f.line), "valid maximum backend reply rejected");
    f.t->fnPayloadD(f.t, f.remotes[0], bytes(data, UINT16_MAX + 1U, false, 0));
    twfRequire(! lineIsAlive(f.remotes[0]) && lineIsAlive(f.line), "oversized reply was not backend-local");
    end();
    begin(false, false, 128);
    uint32_t n = request(data, 0, false);
    sbuf_t  *b = bytes(data, n, true, 320);
    fail_queue = true;
    f.t->fnPayloadU(f.t, f.line, b);
    twfRequire(! lineIsAlive(f.line), "initial queue refusal survived");
    end();
    begin(false, false, 128);
    startUdp();
    fail_map = true;
    datagram(1001, "A", 1, true);
    twfRequire(! lineIsAlive(f.line) && f.inits == 0, "map refusal initialized unpublished backend");
    end();
    memoryFree(data);
}
static void testBackendReentrancy(void)
{
    twfSetCase("UDP callback death, permission fan-out and backend-local recovery");
    for (unsigned boundary = 1; boundary <= 6; ++boundary)
    {
        for (unsigned action = 7; action <= 8; ++action)
        {
            begin(false, true, 128);
            startUdp();
            f.boundary = boundary;
            f.action   = action;
            datagram(1001, "A", 1, true);
            if (boundary == 4)
                f.t->fnPayloadD(f.t, f.remotes[0], bytes("reply", 5, true, 320));
            if (boundary >= 5)
            {
                f.down_paused = true;
                f.t->fnPauseU(f.t, f.line);
                if (boundary == 6)
                {
                    f.down_paused = false;
                    f.t->fnResumeU(f.t, f.line);
                }
            }
            if (action == 7 || boundary <= 4)
                twfRequire(! lineIsAlive(f.line), "association callback death did not settle client");
            else
            {
                twfRequire(lineIsAlive(f.line) && ! lineIsAlive(f.remotes[0]),
                           "backend failure killed association or leaked backend");
                datagram(1002, "B", 1, true);
                twfRequire(f.ports[f.calls_up - 1] == 1002, "backend removal stranded remaining input");
            }
            end();
        }
    }
    begin(false, false, 128);
    startUdp();
    datagram(1001, "A", 1, true);
    datagram(1002, "B", 1, true);
    f.boundary    = 5;
    f.action      = 9;
    f.down_paused = true;
    f.t->fnPauseU(f.t, f.line);
    twfRequire(! lineIsAlive(f.remotes[1]) && lineIsAlive(f.line), "fan-out sibling removal failed");
    f.down_paused = false;
    f.t->fnResumeU(f.t, f.line);
    end();
    begin(false, false, 128);
    startUdp();
    datagram(1001, "A", 1, true);
    datagram(1002, "B", 1, true);
    f.boundary    = 5;
    f.action      = 4;
    f.down_paused = true;
    f.t->fnPauseU(f.t, f.line);
    twfRequire(! ((trojanserver_lstate_t *) lineGetState(f.line, f.t))->prev_paused, "nested fan-out Resume lost");
    for (unsigned i = 0; i < 2; ++i)
        twfRequire(! ((trojanserver_lstate_t *) lineGetState(f.remotes[i], f.t))->next_pause_sent,
                   "stale fan-out Pause survived inline Resume");
    end();
    begin(false, false, 128);
    startUdp();
    datagram(1001, "A", 1, true);
    f.t->fnPauseD(f.t, f.remotes[0]);
    uint8_t  wire[32];
    uint32_t n = frame(wire, 0, 1001, "B", 1);
    f.t->fnPayloadU(f.t, f.line, bytes(wire, 1, true, 320));
    unsigned resumes = f.resumes;
    f.t->fnResumeD(f.t, f.remotes[0]);
    twfRequire(f.resumes == resumes + 1, "incomplete frame withheld producer Resume");
    f.t->fnPayloadU(f.t, f.line, bytes(wire + 1, n - 1, true, 320));
    twfRequire(f.calls_up == 2 && memcmp(f.up, "AB", 2) == 0, "incomplete frame did not recover");
    end();
    begin(false, false, 128);
    startUdp();
    datagram(1001, "A", 1, true);
    datagram(1002, "B", 1, true);
    f.down_paused = true;
    f.t->fnPauseU(f.t, f.line);
    f.t->fnPayloadD(f.t, f.remotes[0], bytes("kept", 4, true, 320));
    f.t->fnFinD(f.t, f.remotes[0]);
    f.down_paused = false;
    f.t->fnResumeU(f.t, f.line);
    twfRequire(f.calls_down == 1 && memcmp(f.down + 11, "kept", 4) == 0, "ready reply did not survive backend removal");
    datagram(1003, "C", 1, true);
    f.down_paused = true;
    f.t->fnPauseU(f.t, f.line);
    f.t->fnPayloadD(f.t, f.remotes[1], bytes("queued", 6, true, 320));
    twfRequire(f.calls_down == 2, "admitted shutdown reply stalled at Pause");
    // Association close may synchronously remove an unvisited sibling.
    f.boundary = 7;
    f.action   = 9;
    f.t->fnFinU(f.t, f.line);
    lineDestroy(f.line);
    end();
}

static void testClosingSiblingCallbacks(void)
{
    twfSetCase("association teardown suppresses a still-live backend sibling's reply and Est");
    begin(false, false, 128);
    startUdp();
    f.auto_est = false;
    datagram(1001, "A", 1, true);
    datagram(1002, "B", 1, true);
    f.boundary = 7;
    f.action   = 13;
    f.t->fnFinU(f.t, f.line);
    twfRequire(f.calls_down == 0 && f.ests == 0, "closing association reflected sibling output");
    lineDestroy(f.line);
    end();
}

static void testAdmittedBatches(void)
{
    twfSetCase("one coalesced UDP batch completes thousands of empty datagrams after Pause");
    uint8_t *wire = memoryAllocate(11 * 4096 + 64);
    for (unsigned i = 0; i < 4096; ++i)
        frame(wire + 11 * i, 0, 1001, NULL, 0);
    begin(false, false, 128);
    startUdp();
    f.boundary = 3;
    f.action   = 1;
    f.t->fnPayloadU(f.t, f.line, bytes(wire, 11 * 4096, false, 320));
    trojanserver_lstate_t *ls = lineGetState(f.line, f.t);
    twfRequire(f.calls_up == 4096 && f.pauses == 1 && ls->input_bytes == 0 && ls->input_head == NULL &&
                   bufferqueueGetBufCount(&ls->pending_up) == 0,
               "Pause or output entry cap stranded accepted empty datagrams");
    end();

    twfSetCase("fragmented UDP prefix, coalesced frames and nested input retain FIFO and suffix");
    begin(false, false, 128);
    startUdp();
    uint32_t n = frame(wire, 0, 1001, "A", 1);
    n += frame(wire + n, 0, 1001, "B", 1);
    uint32_t last = frame(wire + n, 0, 1001, "C", 1);
    f.t->fnPayloadU(f.t, f.line, bytes(wire, 5, true, 320));
    uint8_t nested[32];
    nested[0]            = 'C';
    uint32_t nested_len  = 1 + frame(nested + 1, 0, 1001, "D", 1);
    nested[nested_len++] = 1;
    f.nested             = bytes(nested, nested_len, true, 320);
    f.boundary           = 3;
    f.action             = 11;
    f.t->fnPayloadU(f.t, f.line, bytes(wire + 5, n + last - 6, true, 320));
    ls = lineGetState(f.line, f.t);
    twfRequire(f.calls_up == 4 && memcmp(f.up, "ABCD", 4) == 0 && ls->input_bytes == 1,
               "nested parser input overtook older records or lost incomplete suffix");
    n = frame(wire, 0, 1001, "E", 1);
    f.t->fnPayloadU(f.t, f.line, bytes(wire + 1, n - 1, true, 320));
    twfRequire(f.calls_up == 5 && memcmp(f.up, "ABCDE", 5) == 0 && ls->input_bytes == 0,
               "retained partial header blocked later input");
    end();

    twfSetCase("receiver close in a UDP batch stops all remaining callbacks");
    begin(false, false, 128);
    startUdp();
    n = frame(wire, 0, 1001, "A", 1);
    n += frame(wire + n, 0, 1002, "B", 1);
    f.boundary = 3;
    f.action   = 7;
    f.t->fnPayloadU(f.t, f.line, bytes(wire, n, true, 320));
    twfRequire(! lineIsAlive(f.line) && f.calls_up == 1 && f.remote_count == 1,
               "decoder emitted another callback after association close");
    end();
    twfSetCase("backend Init Finish terminates the admitted carrier batch without dropping one record");
    begin(false, false, 128);
    startUdp();
    f.boundary = 1;
    f.action   = 8;
    f.t->fnPayloadU(f.t, f.line, bytes(wire, n, true, 320));
    twfRequire(! lineIsAlive(f.line) && f.calls_up == 0 && f.remote_count == 1 && f.finishes == 1,
               "backend Init Finish silently dropped its datagram and continued the batch");
    end();
    memoryFree(wire);
}

static void testRetentionAndIndependentDelay(void)
{
    twfSetCase("branch Init reentry uses the 2 MiB and 1,024-entry retention budgets");
    uint8_t *wire = memoryAllocateZero(kTrojanServerMaxWireBytes + 320);
    for (unsigned entries = 0; entries < 2; ++entries)
    {
        for (unsigned overflow = 0; overflow < 2; ++overflow)
        {
            begin(false, false, 128);
            uint32_t n           = request(wire, 0, false);
            f.boundary           = 1;
            f.action             = 12;
            f.admission_entries  = entries ? 1024 : 1;
            f.admission_bytes    = entries ? 0 : kTrojanServerMaxPendingBytes;
            f.overflow_admission = overflow;
            f.t->fnPayloadU(f.t, f.line, bytes(wire, n, false, 320));
            twfRequire(overflow ? ! lineIsAlive(f.line) : f.calls_up == f.admission_entries,
                       "branch Init retention did not settle or drain");
            end();
        }
    }
    twfSetCase("active UDP head and cached metadata remain charged during backend Init");
    begin(false, false, 128);
    startUdp();
    uint32_t n           = frame(wire, 0, 1001, "A", 1);
    f.boundary           = 1;
    f.action             = 12;
    f.admission_entries  = 1;
    f.admission_bytes    = kTrojanServerMaxWireBytes - n;
    f.overflow_admission = true;
    f.t->fnPayloadU(f.t, f.line, bytes(wire, n, false, 320));
    twfRequire(! lineIsAlive(f.line) && f.calls_up == 0, "wire overflow escaped selected-frame accounting");
    end();

    twfSetCase("coalesced 2 MiB TCP body is retained before reentrant Est admission");
    begin(false, false, 128);
    n = request(wire, 3, false);
    memset(wire + n, 'a', kTrojanServerMaxPendingBytes);
    f.boundary = 2;
    f.action   = 5;
    f.t->fnPayloadU(f.t, f.line, bytes(wire, n + kTrojanServerMaxPendingBytes, false, 320));
    twfRequire(! lineIsAlive(f.line) && f.calls_up == 0, "Est hid retained initial body from budget");
    end();

    twfSetCase("pre-Est TCP replies and zero-delay fallback complete under Pause");
    for (unsigned fallback = 0; fallback < 2; ++fallback)
    {
        begin(fallback, false, 128);
        f.auto_est = false;
        n          = request(wire, 0, false);
        if (fallback)
            wire[0] = 'x';
        f.boundary = 1;
        f.action   = 6;
        f.t->fnPayloadU(f.t, f.line, bytes(wire, n, false, 320));
        twfRequire(f.calls_down == 1 && f.down[0] == 'Z' && f.ests == 0, "synchronous Init reply waited for Est");
        f.t->fnPauseD(f.t, f.line);
        f.t->fnPayloadU(f.t, f.line, bytes("X", 1, true, 320));
        twfRequire(fallback ? f.replay[f.replay_len - 1] == 'X' : f.up_len == 1,
                   "admitted TCP or inline fallback waited for Resume");
        end();
    }

    twfSetCase("new input cannot release delayed fallback backlog through Pause");
    begin(true, false, 128);
    ((trojanserver_tstate_t *) tunnelGetState(f.t))->fallback_intentional_delay_ms = 7;
    f.t->fnPayloadU(f.t, f.line, bytes("A", 1, true, 320));
    f.t->fnPauseD(f.t, f.line);
    f.t->fnPayloadU(f.t, f.line, bytes("B", 1, true, 320));
    fallbackFinishDriveDelayedTask();
    twfRequire(f.calls_fallback == 0 && ! g_fallback_finish_task.pending, "independent delayed backlog crossed Pause");
    f.t->fnPayloadU(f.t, f.line, bytes("C", 1, true, 320));
    twfRequire(f.calls_fallback == 0 && ! g_fallback_finish_task.pending, "new input relabeled older delayed backlog");
    f.t->fnResumeD(f.t, f.line);
    twfRequire(g_fallback_finish_task.pending && f.calls_fallback == 0, "Resume skipped intentional delay");
    fallbackFinishDriveDelayedTask();
    twfRequire(f.calls_fallback == 1 && f.replay_len == 3 && memcmp(f.replay, "ABC", 3) == 0,
               "delayed Resume lost replay ordering");
    end();
    memoryFree(wire);
}

static void testPipeFallbackAndPadding(void)
{
    twfSetCase("UDP body/reply pipe pressure, mixed sources and full onward padding");
    uint8_t wire[9000], body[8192];
    memset(body, 'p', sizeof(body));
    for (unsigned fault = 0; fault < 4; ++fault)
    {
        begin(false, false, 128);
        startUdp();
        uint32_t n = frame(wire, 0, 1001, body, sizeof(body));
        for (unsigned off = 0; off < n;)
        {
            unsigned count = min(n - off, 2048U);
            sbuf_t  *part  = bytes(wire + off, count, true, 320);
            if (off + count == n)
            {
                fail_pipe     = fault == 1;
                pressure      = fault == 2;
                reject_growth = fault == 3;
            }
            f.t->fnPayloadU(f.t, f.line, part);
            off += count;
        }
        twfRequire(f.calls_up == 1 && f.up_len == sizeof(body) && memcmp(f.up, body, sizeof(body)) == 0 &&
                       f.headroom >= 320,
                   "split pipe body fallback lost bytes or padding");
#if WW_HAVE_SPLICE
        if (fault == 1)
            twfRequire(pipe_refusals != 0 && ! f.last_splice, "pipe refusal not exercised");
        if (fault == 2)
            twfRequire(moves >= 2 && ! f.last_splice, "partial transfer refusal not exercised");
        if (fault == 3)
            twfRequire(growth_refusals != 0 && ! f.last_splice, "one-page growth refusal not exercised");
#endif
        end();
    }
    begin(false, false, 128);
    bufferpoolUpdateAllocationPaddings(f.env.pool, 352, 352, 352, 32);
    startUdp();
    datagram(1001, "A", 1, true);
    sbuf_t *reply = bytes("body", 4, true, 0);
    f.t->fnPayloadD(f.t, f.remotes[0], reply);
    twfRequire(f.headroom >= 352 - 11 && memcmp(f.down + 11, "body", 4) == 0,
               "insufficient-pad reply lost onward headroom");
    end();
    begin(false, false, 128);
    startUdp();
    datagram(1001, "A", 1, true);
    reply = bytes("body", 4, true, 320);
    sbufShiftLeft(reply, 3);
    sbufWrite(reply, "pre", 3);
    f.t->fnPayloadD(f.t, f.remotes[0], reply);
    twfRequire(f.down_len == 18 && memcmp(f.down + 11, "prebody", 7) == 0, "reply prepend overwrote resident prefix");
    end();
}

static void testReplyFormsAndRefusal(void)
{
    twfSetCase("UDP reply address forms, partial pipe pressure and allocation refusal");
    uint8_t wire[512], expected[512], body[1024];
    memset(body, 'r', sizeof(body));
    for (unsigned form = 0; form < 4; ++form)
    {
        begin(false, false, 128);
        startUdp();
        uint32_t n = frame(wire, form, 1001, "A", 1);
        f.t->fnPayloadU(f.t, f.line, bytes(wire, n, true, 320));
        sbuf_t *reply = bytes("body", 4, true, 0);
        f.t->fnPayloadD(f.t, f.remotes[0], reply);
        n = frame(expected, form, 1001, "body", 4);
        twfRequire(f.down_len == n && memcmp(f.down, expected, n) == 0,
                   "reply address or insufficient-pad body changed");
        end();
    }
    begin(false, false, 128);
    startUdp();
    datagram(1001, "A", 1, true);
    sbuf_t *reply = bytes(body, sizeof(body), true, 0);
    pressure      = true;
    moves         = 0;
    f.t->fnPayloadD(f.t, f.remotes[0], reply);
    twfRequire(f.down_len == sizeof(body) + 11 && memcmp(f.down + 11, body, sizeof(body)) == 0,
               "partial reply-pipe transfer lost bytes");
#if WW_HAVE_SPLICE
    twfRequire(moves >= 2 && ! f.last_splice, "reply pressure fallback not exercised");
#endif
    end();
}

int main(void)
{
    twfRequire(wCryptoGlobalInit() == kWCryptoOk, "crypto init failed");
    twfRequire(globalstateInitializeSecureRandom(), "secure random initialization failed");
    twfRequire(frandGlobalInit(), "random initialization failed");
    sha224_hash_t hash;
    twfRequire(wCryptoSHA224(&hash, (const unsigned char *) "test", 4) == kWCryptoOk, "hash failed");
    asciiHexEncodeBytesLower(hash.bytes, SHA224_DIGEST_SIZE, hash_hex);
    testRequests();
    testAuthentication();
    testReentrancy();
    testUdpFrames();
    testUdpPressure();
    testFallback();
    testFallbackLocalReplies();
    testLimitsAndFailures();
    testBackendReentrancy();
    testClosingSiblingCallbacks();
    testAdmittedBatches();
    testRetentionAndIndependentDelay();
    testPipeFallbackAndPadding();
    testReplyFormsAndRefusal();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    puts("TrojanServer splice, authentication, fallback, UDP pressure and ownership tests passed");
    return 0;
}
