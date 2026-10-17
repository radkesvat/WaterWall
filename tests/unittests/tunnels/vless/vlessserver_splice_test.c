/*
 * Covers: vlessserver splice; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: testUdpPressureRelease, testFirstResponse, testOrdinaryResponsePadding, testResponseOrdering,
 * testRequests, testFallback, testFallbackLocalReplies, testCredentialSnapshots; the driver lists the
 * remaining cases
 * Checks: Assertion labels include: inventory exhaustion; server destroyed borrowed client; exact
 * reentry retention budget rejected; reentry retention overflow accepted
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.vlessserver_no_splice_unit; waterwall.vlessserver_splice_unit
 * Organization: Ordinary, prefix and pipe inputs reuse this side's protocol fixture, allocation/queue
 * fault seams and buffer-read/ownership oracle. The opposite side is compiled separately; the no-splice
 * variant runs the same named case list.
 */
#include "AuthenticationClient/interface.h"
#include "VlessServer/interface.h"
#include "VlessServer/internal.h"
#include "fixtures/protocols/fallback_finish_lifetime_fixture.h"
#include "fixtures/protocols/splice_source.h"

#if WW_HAVE_SPLICE
#include <fcntl.h>
#include <unistd.h>
#endif

static bool     fail_queue;
static bool                         pressure, immediate_pressure;
static unsigned                     moves, pressure_refusals;
static test_splice_inventory_hold_t held_pipes;
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
ssize_t __real_splice(int, off_t *, int, off_t *, size_t, unsigned);
ssize_t __wrap_splice(int, off_t *, int, off_t *, size_t, unsigned);
ssize_t __wrap_splice(int in, off_t *oi, int out, off_t *oo, size_t count, unsigned flags)
{
    /* Inject destination-pipe pressure, not refusal by the discard sink. */
    if ((pressure || immediate_pressure) && fcntl(out, F_GETPIPE_SZ) < 0)
        return __real_splice(in, oi, out, oo, count, flags);
    if (immediate_pressure)
    {
        ++pressure_refusals;
        errno = EAGAIN;
        return -1;
    }
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

static bool bare_local_user;

static unsigned              auth_calls;
static bool                  auth_available = true, auth_match = true;
bool                         __wrap_authenticationclientCanAuthenticate(tunnel_t *t);
bool                         __wrap_authenticationclientCanAuthenticate(tunnel_t *t)
{
    discard t;
    return auth_available;
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
    bool             source_paused, resume_input, pause_replacement, close_on_resume;
    bool             require_active_reply;
    unsigned         source_pauses, source_resumes;
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
        const uint16_t source_padding = padding == 320 ? bufferpoolGetSpliceBufferPadding(f.env.pool) : padding;
        b                             = twfTrackAcquired(testSpliceSourceBuffer(source_padding, n));
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
        tunnelDownStreamPause(f.t, l);
        if (action == 2)
            tunnelDownStreamResume(f.t, l);
    }
    if (action == 3 || action == 4)
    {
        f.down_paused = true;
        tunnelUpStreamPause(f.t, f.line);
        if (action == 4)
        {
            f.down_paused = false;
            tunnelUpStreamResume(f.t, f.line);
        }
    }
    if (action == 5)
        tunnelUpStreamPayload(f.t, f.line, bytes("C", 1, false, 320));
    if (action == 6)
        tunnelDownStreamPayload(f.t, l, bytes("Z", 1, true, 320));
    if (action == 7)
    {
        tunnelUpStreamFin(f.t, f.line);
        twfRequire(lineIsAlive(f.line), "server destroyed borrowed client");
        lineDestroy(f.line);
    }
    if (action == 8)
        tunnelDownStreamFin(f.t, l);
    if (action == 9 && f.remote_count > 1)
    {
        line_t *target = f.remotes[1];
        if (boundary == 7 && target == l && f.remote_count > 2)
            target = f.remotes[2];
        if (lineIsAlive(target))
            tunnelDownStreamFin(f.t, target);
    }
    if (action == 10)
        tunnelDownStreamEst(f.t, l);
    if (action == 11)
    {
        sbuf_t *nested = f.nested;
        f.nested       = NULL;
        tunnelUpStreamPayload(f.t, f.line, nested);
    }
    if (action == 12)
    {
        uint8_t *data = memoryAllocateZero(f.admission_bytes);
        for (unsigned i = 0; i < f.admission_entries; ++i)
            tunnelUpStreamPayload(f.t, f.line, bytes(data, f.admission_bytes, false, 320));
        twfRequire(lineIsAlive(f.line), "exact reentry retention budget rejected");
        if (f.overflow_admission)
        {
            tunnelUpStreamPayload(f.t, f.line, bytes(data, f.admission_bytes == 0 ? 0 : 1, false, 320));
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
                tunnelDownStreamPayload(f.t, f.remotes[i], bytes("late", 4, true, 320));
                tunnelDownStreamEst(f.t, f.remotes[i]);
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
        if (f.require_active_reply)
            twfRequire(tunnelIsActiveForLine(f.t, l), "server bypassed during an active response batch");
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
    if (t == f.prev)
    {
        twfRequire(l == f.line, "source Pause used a remote line");
        f.source_paused = true;
        ++f.source_pauses;
    }
    ++f.pauses;
    act(5, l);
}
static void onResume(tunnel_t *t, line_t *l)
{
    if (t == f.prev)
    {
        twfRequire(l == f.line, "source Resume used a remote line");
        f.source_paused = false;
        ++f.source_resumes;
        if (f.close_on_resume)
        {
            tunnelUpStreamFin(f.t, l);
            lineDestroy(l);
            return;
        }
        if (f.resume_input)
        {
            f.resume_input = false;
            twfRequire(! lineIsAlive(f.remotes[0]), "source resumed before old backend was destroyed");
            if (f.pause_replacement)
            {
                f.boundary = 1;
                f.action   = 1;
            }
            const uint8_t wire[] = {0, 1, 'B'};
            tunnelUpStreamPayload(f.t, l, bytes(wire, sizeof(wire), true, 320));
        }
    }
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
        const char *username = f.database ? "alice" : ((vlessserver_tstate_t *) tunnelGetState(f.t))->users[0].username;
        twfRequire(lineHasAuthenticatedCredentials(
                       l, username, f.database ? "test" : "42424242-4242-4242-4242-424242424242") &&
                       (username != NULL || lineGetAuthenticatedUsername(l) == NULL),
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
        tunnelDownStreamEst(f.t, l);
}
static void begin(bool fallback, bool database, uint32_t pool)
{
    memoryZero(&f, sizeof(f));
    fail_queue = pressure = immediate_pressure = false;
    moves = pressure_refusals = auth_calls               = 0;
    reads                                                = 0;
    auth_available = auth_match = true;
    fallbackFinishResetScheduledTask();
    twfWorkerEnvSetupWithBufferSizes(&f.env, pool, 512, 320, 8192, pool);
    f.metadata                    = nodeVlessServerGet();
    f.metadata.hash_next          = 1;
    f.metadata.next               = (char *) "next";
    f.metadata.node_settings_json = cJSON_Parse(
        bare_local_user
            ? "{\"uuid\": \"42424242-4242-4242-4242-424242424242\"}"
            : "{\"users\": [{\"username\": \"alice\", \"uuid\": \"42424242-4242-4242-4242-424242424242\"}]}");
    bare_local_user = false;
    f.t             = vlessserverTunnelCreate(&f.metadata);
    twfRequire(f.t != NULL, "server construction failed");
    f.prev     = twfCreatePrevTunnel(&f.trace);
    f.next     = twfCreateNextTunnel(&f.trace);
    f.fallback = twfCreateNextTunnel(&f.trace);
    tunnelBind(f.prev, f.t);
    tunnelBind(f.t, f.next);
    f.prev->chain_index     = 0;
    f.t->chain_index        = 1;
    f.next->chain_index     = 2;
    f.fallback->chain_index = 3;
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
    tunnelUpStreamInit(f.t, f.line);
}
static void end(void)
{
    f.action = 0;
    if (lineIsAlive(f.line))
    {
        tunnelUpStreamFin(f.t, f.line);
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
    testSpliceInventoryReleaseHeld(&held_pipes);
    twfWorkerEnvTeardown(&f.env);
}
static void startUdp(void)
{
    uint8_t  wire[320];
    uint32_t n = request(wire, 0, true);
    tunnelUpStreamPayload(f.t, f.line, bytes(wire, n, true, 320));
}
static void datagram(uint16_t port, const void *data, uint32_t n, bool pipe)
{
    uint8_t  wire[9000];
    discard  port;
    uint32_t len = frame(wire, data, n);
    tunnelUpStreamPayload(f.t, f.line, bytes(wire, len, pipe && len <= 4096, 320));
}

static void testUdpPressureRelease(void)
{
    twfSetCase("paused UDP backend close releases a stopped source exactly once");
    begin(false, false, 128);
    startUdp();
    datagram(443, "A", 1, true);
    tunnelDownStreamPause(f.t, f.remotes[0]);
    twfRequire(f.source_paused, "backend did not stop the source");
    tunnelDownStreamFin(f.t, f.remotes[0]);
    twfRequire(! f.source_paused && f.source_resumes == 1, "removed backend stranded the paused source");
    if (! f.source_paused)
        datagram(443, "B", 1, true);
    twfRequire(f.remote_count == 2 && f.calls_up == 2 && ! memcmp(f.up, "AB", 2) && f.ests == 1 &&
                   f.branch_finishes == 0,
               "released source did not replace backend or reflected Finish");
    tunnelDownStreamResume(f.t, f.remotes[1]);
    tunnelDownStreamPause(f.t, f.remotes[1]);
    tunnelDownStreamPause(f.t, f.remotes[1]);
    tunnelDownStreamResume(f.t, f.remotes[1]);
    tunnelDownStreamResume(f.t, f.remotes[1]);
    twfRequire(f.source_pauses == 2 && f.source_resumes == 2, "duplicate signals created extra holds/releases");
    tunnelDownStreamFin(f.t, f.remotes[1]);
    twfRequire(f.source_resumes == 2, "unpaused close emitted Resume");
    end();

    twfSetCase("Resume reentry can close client or install an immediately paused replacement");
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        begin(false, false, 128);
        startUdp();
        datagram(443, "A", 1, true);
        tunnelDownStreamPause(f.t, f.remotes[0]);
        /* Receiver pressure is independent and must reach the replacement. */
        tunnelUpStreamPause(f.t, f.line);
        f.close_on_resume   = mode == 0;
        f.resume_input      = mode != 0;
        f.pause_replacement = mode == 2;
        tunnelDownStreamFin(f.t, f.remotes[0]);
        twfRequire(f.source_resumes == 1 && ! lineIsAlive(f.remotes[0]), "old backend pressure was not settled");
        if (mode == 0)
            twfRequire(! lineIsAlive(f.line) && f.remote_count == 1, "Resume closure restarted the association");
        else
        {
            vlessserver_lstate_t *ls = lineGetState(f.line, f.t);
            twfRequire(lineIsAlive(f.line) && f.remote_count == 2 && ls->udp_remote_line == f.remotes[1] &&
                           f.calls_up == 2 && f.ests == 1 && f.pauses == (mode == 2 ? 4 : 3) &&
                           f.source_paused == (mode == 2),
                       "replacement pressure or association state was overwritten");
            tunnelDownStreamResume(f.t, f.remotes[1]);
            twfRequire(! f.source_paused, "replacement pressure could not release");
        }
        end();
    }
    twfSetCase("client teardown and shutdown suppress backend pressure restart");
    for (unsigned shutdown = 0; shutdown < 2; ++shutdown)
    {
        begin(false, false, 128);
        startUdp();
        datagram(443, "A", 1, true);
        tunnelDownStreamPause(f.t, f.remotes[0]);
        if (shutdown)
        {
            wloopCloseNormalAdmission(f.env.loop);
            wloopQuiesceNormalWork(f.env.loop);
            tunnelDownStreamFin(f.t, f.remotes[0]);
            twfRequire(lineIsAlive(f.line), "shutdown backend close destroyed borrowed client");
        }
        else
        {
            tunnelUpStreamFin(f.t, f.line);
            lineDestroy(f.line);
        }
        twfRequire(f.source_resumes == 0 && ! lineIsAlive(f.remotes[0]), "teardown restarted source work");
        end();
    }
}

static void testFirstResponse(void)
{
    twfSetCase("first TCP/UDP reply combines the response header without gating Est or later splice");
    for (unsigned udp = 0; udp < 2; ++udp)
        for (unsigned early = 0; early < 2; ++early)
            for (unsigned mode = 0; mode < 3; ++mode)
            {
                begin(false, false, 128);
                f.auto_est = ! early;
                uint8_t  wire[320];
                uint32_t n = request(wire, 0, udp);
                if (udp)
                    n += frame(wire + n, "A", 1);
                tunnelUpStreamPayload(f.t, f.line, bytes(wire, n, false, 320));
                line_t *backend = udp ? f.remotes[0] : f.line;
                twfRequire(f.ests == ! early && f.calls_down == 0, "Est emitted a standalone response header");
                tunnelUpStreamPause(f.t, f.line);
                tunnelUpStreamResume(f.t, f.line);
                if (! udp)
                    tunnelDownStreamPayload(f.t, backend, bytes("", 0, mode != 0, 320));
                twfRequire(f.calls_down == 0, "Resume or empty input emitted a standalone response header");
                twfRequire(tunnelIsActiveForLine(f.t, f.line), "server bypassed before its first response");

                sbuf_t *first = bytes(mode == 2 ? "ply" : "reply", mode == 2 ? 3 : 5, mode != 0, mode == 0 ? 0 : 320);
                if (mode == 2)
                {
                    sbufShiftLeft(first, 2);
                    sbufWrite(first, "re", 2);
                }
                /* A synchronous admitted reply can complete after receiver Pause. */
                tunnelUpStreamPause(f.t, f.line);
                tunnelDownStreamPayload(f.t, backend, first);
                const uint8_t  tcp_expected[] = {0, 0, 'r', 'e', 'p', 'l', 'y'};
                const uint8_t  udp_expected[] = {0, 0, 0, 5, 'r', 'e', 'p', 'l', 'y'};
                const uint8_t *expected       = udp ? udp_expected : tcp_expected;
                size_t         length         = udp ? sizeof(udp_expected) : sizeof(tcp_expected);
                uint16_t       minimum_padding =
                    320 - kVlessServerResponseLen - kVlessServerUdpHeaderLen - (mode == 2 ? 2 : 0);
                twfRequire(f.calls_down == 1 && f.down_len == length && ! f.last_splice &&
                               memoryCompare(f.down, expected, length) == 0 && f.headroom >= minimum_padding,
                           "first response was split, corrupted, pipe-backed, or lost onward padding");
                twfRequire(tunnelIsActiveForLine(f.t, f.line) == (udp != 0),
                           "first response retired UDP state or retained settled TCP state");
                if (udp)
                    twfRequire(tunnelIsActiveForLine(f.t, backend), "server bypassed its owned UDP backend");
                else
                    twfRequireLineStateZeroed(f.line, f.t, "bypassed TCP response retained server state");
                tunnelDownStreamEst(f.t, backend);
                tunnelDownStreamEst(f.t, backend);
                tunnelUpStreamResume(f.t, f.line);
                twfRequire(f.ests == (udp ? 1U : 2U + ! early) && f.calls_down == 1,
                           "repeated Est was suppressed on TCP or repeated the response header");
                sbuf_t *later = bytes("tail", 4, true, 320);
                tunnelDownStreamPayload(f.t, backend, later);
                twfRequire(f.calls_down == 2 && f.last == later && f.last_splice == (WW_HAVE_SPLICE != 0) &&
                               f.down_len == length + (udp ? 6 : 4) &&
                               memoryCompare(f.down + length, udp ? "\0\4tail" : "tail", udp ? 6 : 4) == 0,
                           "later reply lost its representation, repeated the header, or changed bytes");
                end();
            }
}

static void testOrdinaryResponsePadding(void)
{
    twfSetCase("ordinary first replies reuse available padding for both response and UDP headers");
    for (unsigned udp = 0; udp < 2; ++udp)
        for (unsigned padding = 0; padding <= 4; ++padding)
        {
            begin(false, false, 128);
            uint8_t  wire[320];
            uint32_t n = request(wire, 0, udp);
            if (udp)
                n += frame(wire + n, "A", 1);
            tunnelUpStreamPayload(f.t, f.line, bytes(wire, n, false, 320));
            sbuf_t *first = bytes("reply", 5, false, 320);
            /* Leave exact headroom, including values smaller than buffer alignment. */
            sbufShiftLeft(first, sbufGetLeftCapacity(first) - padding);
            sbufSetLength(first, 5);
            sbufWrite(first, "reply", 5);
            tunnelDownStreamPayload(f.t, udp ? f.remotes[0] : f.line, first);
            const uint8_t tcp_expected[] = {0, 0, 'r', 'e', 'p', 'l', 'y'};
            const uint8_t udp_expected[] = {0, 0, 0, 5, 'r', 'e', 'p', 'l', 'y'};
            size_t        length         = udp ? sizeof(udp_expected) : sizeof(tcp_expected);
            unsigned      headers        = udp ? 4 : 2;
            twfRequire(f.calls_down == 1 && f.down_len == length && ! f.last_splice &&
                           memoryCompare(f.down, udp ? udp_expected : tcp_expected, length) == 0,
                       "ordinary first reply changed bytes or was split");
            if (padding >= headers)
            {
                twfRequire(f.headroom == padding - headers, "ordinary first reply did not use its reserved headroom");
#ifndef DEBUG
                /* Debug queue admission deliberately duplicates ordinary buffers. */
                twfRequire(f.last == first, "ordinary first reply was copied despite sufficient headroom");
#endif
            }
            else
                twfRequire(f.headroom >= 320 - 4, "replacement response lost onward padding");
            twfRequire(f.metadata.required_padding_left == 4, "VlessServer did not advertise both first UDP headers");
            end();
        }
}

static void testResponseOrdering(void)
{
    twfSetCase("combined first response preserves reentry order, full-sized bodies and silent close");
    uint8_t wire[320];
    begin(false, false, 128);
    uint32_t n = request(wire, 0, false);
    tunnelUpStreamPayload(f.t, f.line, bytes(wire, n, false, 320));
    f.boundary = 4;
    f.action   = 6;
    f.require_active_reply = true;
    tunnelDownStreamPayload(f.t, f.line, bytes("X", 1, true, 320));
    const uint8_t expected[] = {0, 0, 'X', 'Z'};
    twfRequire(f.calls_down == 2 && f.down_len == sizeof(expected) &&
                   memoryCompare(f.down, expected, sizeof(expected)) == 0,
               "reentrant reply split or repeated the response header, or overtook the first body");
    twfRequire(! tunnelIsActiveForLine(f.t, f.line), "server retained settled reentrant TCP response state");
    twfRequireLineStateZeroed(f.line, f.t, "bypassed reentrant response retained server state");
    end();

    begin(false, false, 128);
    tunnelUpStreamPayload(f.t, f.line, bytes(wire, n, false, 320));
    uint8_t *body = memoryAllocate(kVlessServerMaxPendingBytes);
    memorySet(body, 'L', kVlessServerMaxPendingBytes);
    tunnelDownStreamPayload(f.t, f.line, bytes(body, kVlessServerMaxPendingBytes, false, 320));
    twfRequire(lineIsAlive(f.line) && f.calls_down == 1 && f.down_len == kVlessServerMaxPendingBytes + 2 &&
                   f.down[0] == 0 && f.down[1] == 0 &&
                   memoryCompare(f.down + 2, body, kVlessServerMaxPendingBytes) == 0,
               "full-sized first reply was split, truncated or rejected");
    memoryFree(body);
    end();

    for (unsigned udp = 0; udp < 2; ++udp)
    {
        begin(false, false, 128);
        n = request(wire, 0, udp);
        if (udp)
            n += frame(wire + n, "A", 1);
        tunnelUpStreamPayload(f.t, f.line, bytes(wire, n, false, 320));
        tunnelDownStreamFin(f.t, udp ? f.remotes[0] : f.line);
        twfRequire(f.ests == 1 && f.calls_down == 0, "backend Finish sent a header without a reply");
        end();
        twfRequire(f.calls_down == 0, "source Finish flushed a standalone response header");
    }
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
            tunnelUpStreamPayload(f.t, f.line, bytes(wire, split, true, 320));
            if (split != n + 2)
                tunnelUpStreamPayload(f.t, f.line, bytes(wire + split, n + 2 - split, true, 320));
            twfRequire(f.inits == 1 && f.ests == 1 && auth_calls == 1, "request repeated authentication or Init/Est");
            twfRequire(f.up_len == 2 && memcmp(f.up, "AB", 2) == 0, "TCP request consumed body");
            twfRequire(f.parser_reads == (WW_HAVE_SPLICE ? n : 0), "TCP parser read body bytes");
            tunnelDownStreamPayload(f.t, f.line, bytes("first", 5, true, 320));
            for (unsigned dir = 0; dir < 2; ++dir)
            {
                sbuf_t *b = bytes("opaque", 6, true, 320);
                if (dir)
                    tunnelUpStreamPayload(f.t, f.line, b);
                else
                    tunnelDownStreamPayload(f.t, f.line, b);
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
    tunnelUpStreamPayload(f.t, f.line, b);
    twfRequire(f.parser_reads == 0 && memcmp(f.up, "AB", 2) == 0, "resident request header read a pipe body");
    end();
    begin(false, false, 128);
    uint8_t *large = memoryAllocate(1024 * 1024 + 320);
    n              = request(large, 3, false);
    memset(large + n, 'L', 1024 * 1024);
    tunnelUpStreamPayload(f.t, f.line, bytes(large, 17, true, 320));
    tunnelUpStreamPayload(f.t, f.line, bytes(large + 17, n + 1024 * 1024 - 17, false, 320));
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
        tunnelUpStreamPayload(f.t, f.line, bytes(probe, sizeof(probe), true, 320));
        tunnelUpStreamPayload(f.t, f.line, bytes(probe, sizeof(probe), true, 320));
        tunnelUpStreamPayload(f.t, f.line, bytes(probe, sizeof(probe), false, 320));
        twfRequire(f.fallback_inits == 1 && f.calls_fallback == 0 && g_fallback_finish_task.pending,
                   "fallback delay not retained");
        twfRequire(g_fallback_finish_task.delay_ms >= 6 && g_fallback_finish_task.delay_ms <= 8,
                   "fallback jitter changed");
        if (fault == 1)
            held_pipes = testSpliceInventoryHoldAvailable(getCurrentEventWorkerBufferPool());
        pressure           = fault == 2;
        immediate_pressure = fault == 3;
        fallbackFinishDriveDelayedTask();
        twfRequire(f.calls_fallback == 1 && f.replay_len == 6144, "fallback batch not delivered once");
        tunnelDownStreamEst(f.t, f.line);
        tunnelDownStreamEst(f.t, f.line);
        twfRequire(tunnelIsActiveForLine(f.t, f.line) && f.ests == 3,
                   "fallback bypassed its selected branch or suppressed repeated Est");
        for (size_t i = 0; i < f.replay_len; ++i)
            twfRequire(f.replay[i] == 'x', "fallback replay corrupted");
        end();
    }
    begin(true, false, 128);
    ((vlessserver_tstate_t *) tunnelGetState(f.t))->fallback_intentional_delay_ms = 7;
    g_fallback_finish_task.refuse                                                 = true;
    tunnelUpStreamPayload(f.t, f.line, bytes("probe", 5, true, 320));
    twfRequire(! lineIsAlive(f.line), "task refusal did not close fallback");
    end();
}

static bool local_reply_pipe;
static void localFallbackReplyAndFinish(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    capture(t, l, buf);
    tunnelDownStreamPayload(f.t, l, bytes("response", 8, local_reply_pipe, 320));
    if (lineIsAlive(l))
        tunnelDownStreamFin(f.t, l);
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
                tunnelUpStreamPayload(f.t, f.line, bytes("probe", 5, pipe != 0, 320));
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
        tunnelUpStreamPayload(f.t, f.line, bytes("probe", 5, true, 320));
        f.down_paused = true;
        tunnelUpStreamPause(f.t, f.line);
        f.boundary = 4;
        f.action   = action;
        tunnelDownStreamPayload(f.t, f.line, bytes("A", 1, true, 320));
        tunnelDownStreamPayload(f.t, f.line, bytes("B", 1, false, 320));
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
    tunnelUpStreamPayload(f.t, f.line, bytes("probe", 5, true, 320));
    twfRequire(f.down_len == 8 && ! lineIsAlive(f.line) && f.branch_finishes == 1 && f.finishes == 0,
               "source close during fallback reply was not settled once");
    end();
}
static void testCredentialSnapshots(void)
{
    twfSetCase("complete local credential snapshots with optional username");
    for (unsigned bare = 0; bare < 2; ++bare)
    {
        bare_local_user = bare != 0;
        begin(true, false, 128);
        uint8_t  wire[320];
        uint32_t n = request(wire, 0, false);
        tunnelUpStreamPayload(f.t, f.line, bytes(wire, n, true, 320));
        vlessserver_lstate_t *ls = lineGetState(f.line, f.t);
        twfRequire(lineIsAlive(f.line) && f.inits == 1 && f.fallback_inits == 0 && ls->auth_password != NULL &&
                       (ls->auth_username == NULL) == (bare != 0),
                   "local credential snapshot lost identity or optional username");
        tunnelDownStreamPayload(f.t, f.line, bytes("X", 1, false, 320));
        twfRequire(
            ! tunnelIsActiveForLine(f.t, f.line) &&
                lineHasAuthenticatedCredentials(f.line, bare ? NULL : "alice", "42424242-4242-4242-4242-424242424242"),
            "TCP bypass discarded authenticated line credentials");
        end();
    }
}

static void testAuthentication(void)
{
    twfSetCase("first callback credentials and authenticated rejection");
    uint8_t wire[512];
    for (unsigned length = 0; length < 17; ++length)
    {
        begin(true, false, 128);
        request(wire, 0, false);
        tunnelUpStreamPayload(f.t, f.line, bytes(wire, length, true, 320));
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
        tunnelUpStreamPayload(f.t, f.line, bytes(wire, n, true, 320));
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
    tunnelUpStreamPayload(f.t, f.line, b);
    twfRequire(auth_calls == 1 && f.inits == 0, "mixed 17-byte credential was not authenticated");
    tunnelUpStreamPayload(f.t, f.line, bytes(wire + 17, n - 17, true, 320));
    twfRequire(auth_calls == 1 && f.inits == 1, "cached authentication repeated");
    end();
    begin(true, true, 128);
    request(wire, 0, false);
    wire[17] = 255;
    tunnelUpStreamPayload(f.t, f.line, bytes(wire, 18, true, 320));
    twfRequire(lineIsAlive(f.line), "incomplete addons rejected early");
    memset(wire, 0, 255);
    tunnelUpStreamPayload(f.t, f.line, bytes(wire, 255, true, 320));
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
        tunnelUpStreamPayload(f.t, f.line, bytes(wire, split, true, 320));
        twfRequire(f.calls_up == 0, "incomplete UDP emitted");
        tunnelUpStreamPayload(f.t, f.line, bytes(wire + split, n - split, true, 320));
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
            tunnelUpStreamPayload(f.t, f.line, bytes(wire + off, count, n != 1500, 320));
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
    tunnelUpStreamPayload(f.t, f.line, bytes(wire, n, true, 320));
    twfRequire(f.calls_up == 2 && ! memcmp(f.up, "AB", 2), "Pause stopped accepted UDP batch");
    const uint8_t suffix[] = {1, 'C'};
    tunnelUpStreamPayload(f.t, f.line, bytes(suffix, 2, true, 320));
    twfRequire(f.calls_up == 3 && f.up[2] == 'C', "UDP incomplete suffix lost");
    for (unsigned pad = 0; pad <= 320; pad += 320)
    {
        tunnelDownStreamPayload(f.t, f.remotes[0], bytes("reply", 5, true, pad));
        twfRequire(! memcmp(f.down + f.down_len - 7, "\0\5reply", 7), "UDP reply prepend corrupted pipe");
    }
    size_t before = f.down_len;
    tunnelDownStreamPayload(f.t, f.remotes[0], bytes(body, 0, false, 0));
    twfRequire(f.down_len == before + 2 && ! memcmp(f.down + before, "\0\0", 2), "empty UDP reply lost its frame");
    before = f.down_len;
    tunnelDownStreamPayload(f.t, f.remotes[0], bytes(body, 65536, false, 0));
    twfRequire(f.down_len == before && lineIsAlive(f.remotes[0]), "oversized local reply changed drop policy");
    tunnelDownStreamPayload(f.t, f.remotes[0], bytes(body, 65535, false, 0));
    twfRequire(f.down_len == before + 65537, "maximum reply rejected");
    tunnelDownStreamFin(f.t, f.remotes[0]);
    datagram(443, "D", 1, true);
    twfRequire(f.remote_count == 2 && f.ests == 1 && f.up[3] == 'D', "backend replacement lost Est latch or data");
    tunnelUpStreamPayload(f.t, f.line, bytes("\0\0", 2, true, 320));
    twfRequire(lineIsAlive(f.line) && f.calls_up == 5 && f.up_len == 4,
               "zero-length frame did not deliver one empty datagram");
    end();
    memoryFree(wire);
    memoryFree(body);
}

static void testUdpEmptyFrames(void)
{
    twfSetCase("empty UDP frames preserve datagram delivery, ordering and backend lifetime");
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        begin(false, false, 128);
        uint8_t  wire[320];
        uint32_t n = request(wire, 0, true);
        n += frame(wire + n, NULL, 0);
        tunnelUpStreamPayload(f.t, f.line, bytes(wire, n, mode != 0, 320));
        twfRequire(lineIsAlive(f.line) && f.calls_up == 1 && f.up_len == 0 && f.remote_count == 1 && f.down_len == 0 &&
                       f.ports[0] == 443 && f.headroom >= bufferpoolGetLargeBufferPadding(f.env.pool),
                   "initial empty UDP frame lost its datagram, target or padding");

        tunnelUpStreamPayload(f.t, f.line, bytes("\0", 1, mode != 0, 320));
        twfRequire(lineIsAlive(f.line) && f.calls_up == 1, "incomplete empty-frame header emitted a datagram");
        tunnelUpStreamPayload(f.t, f.line, bytes("\0\0\0", 3, mode != 0, 320));
        twfRequire(lineIsAlive(f.line) && f.calls_up == 3 && f.up_len == 0,
                   "split or consecutive empty frames lost datagrams");

        const uint8_t batch[] = {0, 0, 0, 1, 'A', 0, 0, 0, 1, 'B', 0, 0};
        sbuf_t       *input   = bytes(batch + (mode == 2), sizeof(batch) - (mode == 2), mode != 0, 320);
        if (mode == 2)
        {
            sbufShiftLeft(input, 1);
            sbufWrite(input, batch, 1);
        }
        tunnelUpStreamPayload(f.t, f.line, input);
        twfRequire(lineIsAlive(f.line) && f.calls_up == 8 && f.up_len == 2 && ! memcmp(f.up, "AB", 2) &&
                       f.remote_count == 1 && f.finishes == 0,
                   "empty frames disrupted nonempty UDP boundaries or order");
        vlessserver_lstate_t *ls = lineGetState(f.line, f.t);
        twfRequire(ls->input_bytes == 0 && ls->header_filled == 0 && ls->input_head == NULL &&
                       bufferqueueGetBufCount(&ls->pending_up) == 0,
                   "empty frames retained parser bytes or buffers");

        tunnelDownStreamFin(f.t, f.remotes[0]);
        tunnelUpStreamPayload(f.t, f.line, bytes("\0\0", 2, mode != 0, 320));
        twfRequire(lineIsAlive(f.line) && f.remote_count == 2 && f.calls_up == 9 && f.up_len == 2,
                   "empty UDP frame did not recreate its backend and deliver a datagram");
        datagram(443, "C", 1, mode != 0);
        twfRequire(f.remote_count == 2 && f.calls_up == 10 && f.up_len == 3 && ! memcmp(f.up, "ABC", 3),
                   "nonempty UDP after empty frames lost its backend or payload");
        end();
    }

    for (unsigned close = 0; close < 2; ++close)
    {
        begin(false, false, 128);
        startUdp();
        const uint8_t batch[3000] = {0};
        f.boundary                = 3;
        f.action                  = close ? 7 : 1;
        tunnelUpStreamPayload(f.t, f.line, bytes(batch, sizeof(batch), false, 320));
        twfRequire(f.calls_up == (close ? 1U : 1500U) && f.up_len == 0 && lineIsAlive(f.line) == ! close,
                   "empty UDP batch stopped on Pause or continued after Finish");
        end();
    }
}

static void testEmptyUdpReplies(void)
{
    twfSetCase("first empty UDP reply includes response and datagram headers before or after Est");
    for (unsigned early = 0; early < 2; ++early)
        for (unsigned mode = 0; mode < 3; ++mode)
        {
            begin(false, false, 128);
            f.auto_est = ! early;
            startUdp();
            line_t *backend = f.remotes[0];
            tunnelUpStreamPause(f.t, f.line);
            tunnelDownStreamPayload(f.t, backend, bytes("", 0, mode != 0, mode == 1 ? 320 : 0));
            twfRequire(lineIsAlive(f.line) && lineIsAlive(backend) && f.calls_down == 1 && f.down_len == 4 &&
                           ! memcmp(f.down, "\0\0\0\0", 4) && ! f.last_splice && f.ests == ! early,
                       "first empty UDP reply lost combined headers, waited for Est or used a pipe body");
            tunnelDownStreamEst(f.t, backend);
            tunnelDownStreamEst(f.t, backend);
            tunnelUpStreamResume(f.t, f.line);
            twfRequire(f.ests == 1 && f.calls_down == 1 && f.down_len == 4,
                       "Est or Resume duplicated the first empty UDP reply");
            tunnelDownStreamPayload(f.t, backend, bytes("", 0, mode != 0, mode == 1 ? 320 : 0));
            tunnelDownStreamPayload(f.t, backend, bytes("R", 1, mode != 0, 320));
            twfRequire(f.calls_down == 3 && f.down_len == 9 && ! memcmp(f.down, "\0\0\0\0\0\0\0\1R", 9),
                       "later empty or nonempty UDP reply repeated response metadata or lost ordering");
            end();
        }
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
            tunnelUpStreamPayload(f.t, f.line, bytes(wire, n, true, 320));
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
                tunnelUpStreamPause(f.t, f.line);
            tunnelUpStreamPayload(f.t, f.line, bytes(wire, n, true, 320));
            if (boundary == 4)
                tunnelDownStreamPayload(f.t, udp ? f.remotes[0] : f.line, bytes("reply", 5, true, 320));
            twfRequire(! lineIsAlive(f.line), "callback close left client alive");
            end();
        }
    begin(true, false, 128);
    ((vlessserver_tstate_t *) tunnelGetState(f.t))->fallback_intentional_delay_ms = 7;
    f.boundary                                                                    = 1;
    f.action                                                                      = 7;
    tunnelUpStreamPayload(f.t, f.line, bytes("probe", 5, true, 320));
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
                tunnelUpStreamPause(f.t, f.line);
            twfRequire(f.pauses == 0, "receiver Pause escaped before fallback Init");
            f.boundary = 1;
            f.action   = actions[i];
            tunnelUpStreamPayload(f.t, f.line, bytes("probe", 5, true, 320));
            bool expected = actions[i] == 3 || (actions[i] == 0 && paused);
            twfRequire(fallback_reply_paused == expected,
                       "fallback backend received stale or missing receiver pressure after Init");
            twfRequire(((vlessserver_lstate_t *) lineGetState(f.line, f.t))->response_paused == expected,
                       "fallback receiver pressure state did not follow nested callbacks");
            if (actions[i] == 4)
                twfRequire(f.pauses == 1 && f.resumes == 1, "fallback replayed Pause after nested Resume");
            if (expected)
            {
                tunnelUpStreamResume(f.t, f.line);
                twfRequire(! fallback_reply_paused, "fallback did not release receiver pressure");
            }
            end();
        }

    for (unsigned action = 7; action <= 8; ++action)
    {
        begin(true, false, 128);
        tunnelUpStreamPause(f.t, f.line);
        f.boundary = 5;
        f.action   = action; /* Close from either side during the replayed Pause. */
        tunnelUpStreamPayload(f.t, f.line, bytes("probe", 5, true, 320));
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
                tunnelUpStreamPayload(f.t, f.line, bytes("", 0, false, 320));
                ls->input_dispatching = true;
            }
            else
            {
                unsigned n = request(data, 0, false);
                tunnelUpStreamPayload(f.t, f.line, bytes(data, n, false, 320));
                ls->response_dispatching = true;
            }
            for (unsigned i = 0; i < (entries ? 1024 : 1); ++i)
            {
                sbuf_t *b = bytes(data, entries ? 0 : kVlessServerMaxPendingBytes, false, 320);
                if (direction)
                    tunnelDownStreamPayload(f.t, f.line, b);
                else
                    tunnelUpStreamPayload(f.t, f.line, b);
            }
            buffer_budget_t *budget = direction ? &ls->response_budget : &ls->upstream_budget;
            twfRequire(lineIsAlive(f.line) && bufferbudgetGetUsage(budget).entries == (entries ? 1024 : 1),
                       "exact budget rejected or accounting lost");
            sbuf_t *extra = bytes(data, entries ? 0 : 1, false, 320);
            if (direction)
                tunnelDownStreamPayload(f.t, f.line, extra);
            else
                tunnelUpStreamPayload(f.t, f.line, extra);
            twfRequire(! lineIsAlive(f.line), "output budget overflow accepted");
            end();
        }
    begin(false, false, 128);
    startUdp();
    vlessserver_lstate_t *ls = lineGetState(f.line, f.t);
    ls->input_dispatching    = true;
    tunnelUpStreamPayload(f.t, f.line, bytes(data, kVlessServerMaxBufferedBytes, false, 320));
    twfRequire(lineIsAlive(f.line) && ls->input_bytes == kVlessServerMaxBufferedBytes, "parser equality rejected");
    tunnelUpStreamPayload(f.t, f.line, bytes(data, 1, false, 320));
    twfRequire(! lineIsAlive(f.line), "parser overflow accepted");
    end();
    begin(false, false, 128);
    unsigned n = request(data, 0, false);
    tunnelUpStreamPayload(f.t, f.line, bytes(data, 17, true, 320));
    ls = lineGetState(f.line, f.t);
    twfRequire(ls->input_bytes == 17 && ls->header_filled == 17, "cached metadata charge lost");
    fail_queue = true;
    tunnelUpStreamPayload(f.t, f.line, bytes(data + 17, n - 17, true, 320));
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
        tunnelUpStreamPayload(f.t, f.line, bytes(data, n, true, 320));
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
    tunnelUpStreamPayload(f.t, f.line, b);
    twfRequire(f.inits == 1 && f.parser_reads == 0, "prefix-only request accessed pipe metadata");
    end();
    begin(false, false, 128);
    n = request(wire, 0, false);
    memcpy(wire + n, body, 2048);
    b = bytes(wire, n + 2048, true, 320);
    tunnelUpStreamPayload(f.t, f.line, b);
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
        tunnelUpStreamPayload(f.t, f.line, bytes(wire, 3000, true, 320));
        b = bytes(wire + 3000, n - 3000, true, 320);
        if (fault == 0)
            held_pipes = testSpliceInventoryHoldAvailable(getCurrentEventWorkerBufferPool());
        pressure           = fault == 1;
        immediate_pressure = fault == 2;
        tunnelUpStreamPayload(f.t, f.line, b);
        twfRequire(f.up_len == sizeof(body) && ! memcmp(f.up, body, sizeof(body)), "UDP helper fallback lost bytes");
#if WW_HAVE_SPLICE
        twfRequire(! f.last_splice, "pipe refusal/pressure did not select ordinary fallback");
        if (fault == 0)
            twfRequire(held_pipes.count != 0, "inventory exhaustion not exercised");
        if (fault == 1)
            twfRequire(moves >= 2, "positive-short then pressure not exercised");
        if (fault == 2)
            twfRequire(pressure_refusals != 0, "immediate transfer pressure not exercised");
#endif
        end();
    }
    begin(true, false, 128);
    ((vlessserver_tstate_t *) tunnelGetState(f.t))->fallback_intentional_delay_ms = 7;
    tunnelUpStreamPayload(f.t, f.line, bytes("probe", 5, true, 320));
    tunnelDownStreamPause(f.t, f.line);
    tunnelUpStreamPayload(f.t, f.line, bytes("-tail", 5, false, 320));
    fallbackFinishDriveDelayedTask();
    twfRequire(f.calls_fallback == 1 && f.replay_len == 10 && ! memcmp(f.replay, "probe-tail", 10) &&
                   f.last_splice == (WW_HAVE_SPLICE != 0),
               "due fallback replay waited for Resume, reordered its FIFO or lost its representation");
    tunnelDownStreamResume(f.t, f.line);
    twfRequire(! g_fallback_finish_task.pending && f.calls_fallback == 1,
               "Resume rescheduled an already-drained fallback batch");
    end();
    begin(true, false, 128);
    ((vlessserver_tstate_t *) tunnelGetState(f.t))->fallback_intentional_delay_ms = 7;
    tunnelUpStreamPayload(f.t, f.line, bytes("probe", 5, true, 320));
    tunnelDownStreamPause(f.t, f.line);
    end();
    twfRequire(f.calls_fallback == 1 && f.replay_len == 5 && ! memcmp(f.replay, "probe", 5) &&
                   f.last_splice == (WW_HAVE_SPLICE != 0),
               "source Finish lost the accepted paused fallback batch or its representation");
}

static void testShutdownAdmission(void)
{
    twfSetCase("shutdown refuses new protocol branches but preserves existing forwarding");
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        begin(true, false, 128);
        uint8_t  wire[320];
        uint32_t n = request(wire, 0, mode == 1);
        if (mode == 2)
            wire[0] = 1; // An unsupported version would normally select fallback.
        wloopCloseNormalAdmission(f.env.loop);
        wloopQuiesceNormalWork(f.env.loop);
        tunnelUpStreamPayload(f.t, f.line, bytes(wire, n, true, 320));
        twfRequire(! lineIsAlive(f.line) && f.finishes == 1 && f.inits == 0 && f.fallback_inits == 0 &&
                       f.branch_finishes == 0 && f.remote_count == 0,
                   "late request started or finished an unopened branch");
        end();
    }

    begin(false, false, 128);
    uint8_t  wire[320];
    uint32_t n = request(wire, 0, false);
    tunnelUpStreamPayload(f.t, f.line, bytes(wire, n, true, 320));
    wloopCloseNormalAdmission(f.env.loop);
    wloopQuiesceNormalWork(f.env.loop);
    tunnelUpStreamPayload(f.t, f.line, bytes("final", 5, true, 320));
    tunnelDownStreamPayload(f.t, f.line, bytes("reply", 5, true, 320));
    twfRequire(lineIsAlive(f.line) && f.up_len == 5 && f.down_len == 7 && f.inits == 1,
               "shutdown suppressed existing TCP forwarding or its response header");
    end();

    begin(false, false, 128);
    startUdp();
    datagram(1001, "A", 1, true);
    wloopCloseNormalAdmission(f.env.loop);
    wloopQuiesceNormalWork(f.env.loop);
    datagram(1001, "B", 1, true);
    twfRequire(lineIsAlive(f.line) && f.calls_up == 2 && f.inits == 1, "shutdown suppressed an existing UDP backend");
    tunnelDownStreamFin(f.t, f.remotes[0]);
    twfRequire(lineIsAlive(f.line) && ! lineIsAlive(f.remotes[0]), "backend Finish lost ownership");
    datagram(1001, "C", 1, true);
    twfRequire(! lineIsAlive(f.line) && f.inits == 1 && f.remote_count == 1, "shutdown recreated a closed UDP backend");
    end();
}

int main(void)
{
    twfRequire(wCryptoGlobalInit() == kWCryptoOk, "crypto init failed");
    twfRequire(globalstateInitializeSecureRandom(), "secure random initialization failed");
    twfRequire(frandGlobalInit(), "random initialization failed");
    testUdpPressureRelease();
    testOrdinaryResponsePadding();
    testFirstResponse();
    testResponseOrdering();
    testShutdownAdmission();
    testFallbackReceiverPressure();
    testRepresentationsAndPipePressure();
    testRequests();
    testCredentialSnapshots();
    testAuthentication();
    testUdp();
    testUdpEmptyFrames();
    testEmptyUdpReplies();
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
