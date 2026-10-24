/* Real VMess parser/crypto/authentication with mock neighboring tunnels and a
 * real event-worker loop. Independent V2Ray-format vectors fix the wire input;
 * only wall time is fixed to their timestamp. Cases cover split parsing,
 * reentry, close during response delivery, auth cancellation/deadline, fallback
 * source Finish, UDP backend recreation and queue refusal. CTest:
 * waterwall.vmess_runtime_unit in both Debug and Release. */
#define kTunnelStateSize kAuthenticationFixtureTunnelStateSize
#define kLineStateSize   kAuthenticationFixtureLineStateSize
#include "AuthenticationClient/structure.h"
#undef kLineStateSize
#undef kTunnelStateSize
#include "VmessServer/auth.h"
#include "VmessServer/internal.h"
#include "fixtures/protocols/protocol_est_ordering_fixture.h"
#include "loggers/network_logger.h"

#include "vectors.h"

static master_pool_t *message_master;
static tunnel_t      *refresh_auth;
static size_t         refresh_trials;

wcrypto_status_t __real_vmessAuthIdCheck(vmess_auth_id_ctx_t *ctx, const vmess_prepared_key_t *key,
                                         const uint8_t auth_id[16], uint64_t now, uint64_t *timestamp);
wcrypto_status_t __wrap_vmessAuthIdCheck(vmess_auth_id_ctx_t *ctx, const vmess_prepared_key_t *key,
                                         const uint8_t auth_id[16], uint64_t now, uint64_t *timestamp);
wcrypto_status_t __wrap_vmessAuthIdCheck(vmess_auth_id_ctx_t *ctx, const vmess_prepared_key_t *key,
                                         const uint8_t auth_id[16], uint64_t now, uint64_t *timestamp)
{
    const wcrypto_status_t result = __real_vmessAuthIdCheck(ctx, key, auth_id, now, timestamp);
    if (refresh_auth != NULL && ++refresh_trials == 1)
    {
        authenticationclient_tstate_t *state = tunnelGetState(refresh_auth);
        /* Real table mutation during a trial also verifies that candidate crypto
         * holds neither AuthenticationClient nor users collection locks. */
        mutexLock(&state->control_mutex);
        rwlockWriteLock(&state->users_lock);
        user_t user;
        char   uuid[kWwUuidCanonicalStringLen + 1U];
        wwUuidToCanonicalString(vector_uuid, uuid);
        twfRequire(userCreate(&user, uuid), "refresh UUID construction failed");
        userSetId(&user, 42);
        twfRequire(usersAddUser(state->users, &user), "refresh UUID insertion failed");
        userDestroy(&user);
        ++state->users_generation;
        usersLookupByIdentifier(state->users, 42)->runtime.identity_generation_floor = state->users_generation;
        rwlockWriteUnlock(&state->users_lock);
        mutexUnlock(&state->control_mutex);
        memorySecureZero(uuid, sizeof(uuid));
    }
    return result;
}

int __wrap_gettimeofday(struct timeval *value, void *zone);
int __wrap_gettimeofday(struct timeval *value, void *zone)
{
    discard zone;
    value->tv_sec  = 1700000000;
    value->tv_usec = 0;
    return 0;
}

static void pump(est_fixture_t *f, unsigned milliseconds)
{
    const uint64_t end = getHRTimeUs() + (uint64_t) milliseconds * 1000;
    do
    {
        discard wloopProcessEvents(f->env.loop, 1);
    } while (getHRTimeUs() < end);
}

static void waitInitialized(est_fixture_t *f)
{
    const uint64_t end = getHRTimeUs() + 1000000;
    while (lineIsAlive(f->line) && f->init_count == 0 && getHRTimeUs() < end)
        discard wloopProcessEvents(f->env.loop, 1);
    twfRequire(f->init_count == 1, "VMess did not initialize the selected branch");
}

static void setup(est_fixture_t *f, uint32_t timeout_ms)
{
    estFixtureSetup(f, sizeof(vmessserver_tstate_t), sizeof(vmessserver_lstate_t));
    message_master = masterpoolCreateWithCapacity(16);
    workerMessagesInstallMasterPoolCallbacks(message_master);
    GSTATE.masterpool_messages = message_master;
    mutexInit(&f->env.worker.control_mutex);
    workerMessagesInit(&f->env.worker);
    twfRequire(workerMessagesOpenAdmission(&f->env.worker), "worker message admission failed");
    f->env.loop->status      = WLOOP_STATUS_RUNNING;
    f->prev->chain_index     = 0;
    f->node->chain_index     = 1;
    f->next->chain_index     = 2;
    f->node->fnInitU         = vmessserverTunnelUpStreamInit;
    f->node->fnPayloadU      = vmessserverTunnelUpStreamPayload;
    f->node->fnFinU          = vmessserverTunnelUpStreamFinish;
    f->node->fnPauseU        = vmessserverTunnelUpStreamPause;
    f->node->fnResumeU       = vmessserverTunnelUpStreamResume;
    f->node->fnEstD          = vmessserverTunnelDownStreamEst;
    f->node->fnFinD          = vmessserverTunnelDownStreamFinish;
    f->node->fnPayloadD      = vmessserverTunnelDownStreamPayload;
    f->node->fnPauseD        = vmessserverTunnelDownStreamPause;
    f->node->fnResumeD       = vmessserverTunnelDownStreamResume;
    vmessserver_tstate_t *ts = tunnelGetState(f->node);
    ts->users                = memoryAllocateZero(sizeof(*ts->users));
    memoryCopy(ts->users[0].uuid, vector_uuid, sizeof(vector_uuid));
    ts->users[0].username      = stringDuplicate("vmess-fixture");
    ts->user_count             = 1;
    ts->allow_connect          = true;
    ts->allow_udp              = true;
    ts->handshake_timeout_ms   = timeout_ms;
    ts->auth_max_pending       = 8;
    ts->auth_pending_max_bytes = 4U * 1024U * 1024U;
    ts->auth_cache_max_bytes   = 4U * 1024U * 1024U;
    ts->replay_max_entries     = 64;
    ts->replay                 = vmessReplayCreate(ts->replay_max_entries);
    ts->auth                   = vmessserverAuthCreate(f->node);
    twfRequire(ts->auth != NULL, "VMess authentication runtime creation failed");
    tunnelUpStreamInit(f->node, f->line);
}

static void closeFixture(est_fixture_t *f)
{
    if (lineIsAlive(f->line))
    {
        tunnelUpStreamFin(f->node, f->line);
        lineDestroy(f->line);
    }
    vmessserver_tstate_t         *ts      = tunnelGetState(f->node);
    const ww_lifecycle_context_t *context = wwLifecycleStartupRollback();
    vmessserverAuthOnQuiesceRequest(f->node, context);
    workerMessagesCloseAdmission(&f->env.worker);
    workerMessagesCleanupPending(&f->env.worker);
    vmessserverAuthOnWorkerQuiesce(f->node, 0, context);
    vmessserverAuthOnWorkerStop(f->node, 0, context);
    vmessserverAuthDestroy(ts->auth);
    ts->auth = NULL;
    vmessReplayDestroy(ts->replay);
    ts->replay = NULL;
    memoryFree(ts->users[0].username);
    memoryFree(ts->users);
    ts->users = NULL;
    workerMessagesDestroy(&f->env.worker);
    mutexDestroy(&f->env.worker.control_mutex);
    GSTATE.masterpool_messages = NULL;
    masterpoolMakeEmpty(message_master);
    masterpoolDestroy(message_master);
    message_master = NULL;
    twfRequireLineStateZeroed(f->line, f->node, "VMess line state survives owner Finish");
    estFixtureDestroy(f);
}

static void sendBytes(est_fixture_t *f, const void *bytes, size_t size)
{
    tunnelUpStreamPayload(f->node, f->line, estBytes(f->line, bytes, size));
}

static void sendRequest(est_fixture_t *f, bool udp)
{
    sendBytes(f, udp ? vector_request_udp : vector_request, udp ? sizeof(vector_request_udp) : sizeof(vector_request));
    waitInitialized(f);
}

static void verifyResponse(est_fixture_t *f, const uint8_t *expected, size_t size, bool expected_eof)
{
    twfRequire(f->down_len >= sizeof(vector_response), "VMess response header missing");
    twfRequire(memoryCompare(f->down, vector_response, sizeof(vector_response)) == 0,
               "VMess response header differs from independent vector");
    uint8_t key[16], iv[16];
    twfRequire(vmessResponseKeys(vector_key, vector_iv, key, iv) == kWCryptoOk, "response keys failed");
    vmess_body_ctx_t decoder = {0};
    twfRequire(vmessBodyInit(&decoder,
                             key,
                             iv,
                             VMESS_SECURITY_AES128_GCM,
                             VMESS_OPTION_CHUNK | VMESS_OPTION_MASK | VMESS_OPTION_PADDING,
                             kVmessCmdTcp,
                             false) == kWCryptoOk,
               "response decoder failed");
    uint8_t actual[512];
    size_t  actual_size = 0, cursor = sizeof(vector_response);
    bool    ended = false;
    while (cursor < f->down_len)
    {
        size_t   prefix      = vmessBodyLengthSize(&decoder);
        uint32_t body_length = 0;
        twfRequire(prefix <= f->down_len - cursor, "partial response length");
        twfRequire(vmessBodyLengthOpen(&decoder, f->down + cursor, prefix, &body_length) == kWCryptoOk,
                   "response length invalid");
        cursor += prefix;
        twfRequire(body_length <= f->down_len - cursor, "partial response body");
        size_t received = 0;
        twfRequire(vmessBodyOpen(&decoder,
                                 f->down + cursor,
                                 body_length,
                                 actual + actual_size,
                                 sizeof(actual) - actual_size,
                                 &received,
                                 &ended) == kWCryptoOk,
                   "response authentication failed");
        cursor += body_length;
        actual_size += received;
        twfRequire(! ended || cursor == f->down_len, "output follows the termination record");
    }
    twfRequire(actual_size == size && memoryCompare(actual, expected, size) == 0,
               "response body lost FIFO order or bytes");
    twfRequire(ended == expected_eof, "unexpected termination record count");
    vmessBodyDestroy(&decoder);
}

static void splitParser(void)
{
    est_fixture_t f;
    setup(&f, 1000);
    for (size_t i = 0; i < sizeof(vector_request); ++i)
    {
        sendBytes(&f, vector_request + i, 1);
        pump(&f, 1);
        if (i + 1 < sizeof(vector_request))
            twfRequire(f.init_count == 0, "partial encrypted header opened the target");
    }
    waitInitialized(&f);
    for (size_t i = 0; i < sizeof(vector_frame_3_13_0); ++i)
        sendBytes(&f, vector_frame_3_13_0 + i, 1);
    twfRequire(f.up_len == 11 && memoryCompare(f.up, "Hello VMess", 11) == 0,
               "split VMess record did not decode exactly once");
    closeFixture(&f);
}

static void nestedResponse(est_fixture_t *f, line_t *line)
{
    f->on_down = NULL;
    tunnelDownStreamPayload(f->node, line, estBytes(line, "Y", 1));
}

static void nestedInit(est_fixture_t *f, line_t *line)
{
    tunnelDownStreamPayload(f->node, line, estBytes(line, "X", 1));
    sendBytes(f, vector_frame_3_13_1, sizeof(vector_frame_3_13_1));
    tunnelDownStreamEst(f->node, line);
}

static void reentrantInitAndResponse(void)
{
    est_fixture_t f;
    setup(&f, 1000);
    f.on_init = nestedInit;
    f.on_down = nestedResponse;
    uint8_t request[sizeof(vector_request) + sizeof(vector_frame_3_13_0)];
    memoryCopy(request, vector_request, sizeof(vector_request));
    memoryCopy(request + sizeof(vector_request), vector_frame_3_13_0, sizeof(vector_frame_3_13_0));
    sendBytes(&f, request, sizeof(request));
    waitInitialized(&f);
    twfRequire(f.up_len == 42 && memoryCompare(f.up, "Hello VMess", 11) == 0, "nested input overtook first body");
    for (unsigned i = 0; i < 31; ++i)
        twfRequire(f.up[11 + i] == i, "nested body changed byte order");
    twfRequire(f.est_count == 1, "transport Est was lost or duplicated");
    verifyResponse(&f, (const uint8_t *) "XY", 2, false);
    closeFixture(&f);
}

static void finishDuringResponse(est_fixture_t *f, line_t *line)
{
    f->on_down = NULL;
    tunnelDownStreamFin(f->node, line);
}

static void closeDuringResponseDelivery(void)
{
    est_fixture_t f;
    setup(&f, 1000);
    sendRequest(&f, false);
    f.on_down = finishDuringResponse;
    tunnelDownStreamPayload(f.node, f.line, estBytes(f.line, "X", 1));
    twfRequire(! lineIsAlive(f.line), "Finish during response delivery left the owner alive");
    twfRequire(f.up_finish_count == 0 && f.down_finish_count == 1, "Finish reflected toward its sender");
    verifyResponse(&f, (const uint8_t *) "X", 1, true);
    closeFixture(&f);
}

static unsigned terminal_handoffs;

static void countNextPermission(tunnel_t *t, line_t *line)
{
    discard line;
    ++estContext(t)->pause_count;
}

static void terminalPressure(est_fixture_t *f, line_t *line)
{
    vmessserver_lstate_t *ls = lineGetState(line, f->node);
    if (! ls->output_crypto.ended)
        return;
    ++terminal_handoffs;
    tunnelUpStreamPause(f->node, line);
    tunnelUpStreamResume(f->node, line);
    tunnelUpStreamPause(f->node, line);
    tunnelUpStreamResume(f->node, line);
    sendBytes(f, vector_frame_3_13_0, sizeof(vector_frame_3_13_0));
}

static void queueReplyThenFinishFromEst(est_fixture_t *f, line_t *line)
{
    f->on_est = NULL;
    tunnelDownStreamPayload(f->node, line, estBytes(line, "X", 1));
    tunnelDownStreamFin(f->node, line);
    twfRequire(lineIsAlive(line), "downstream Finish discarded a reply deferred by Est");
    /* The sender's direction is closed even while its accepted reply waits. */
    tunnelUpStreamPause(f->node, line);
    tunnelUpStreamResume(f->node, line);
    sendBytes(f, vector_frame_3_13_0, sizeof(vector_frame_3_13_0));
}

static void queueReplyThenFinishFromPayload(est_fixture_t *f, line_t *line)
{
    f->on_down = terminalPressure;
    tunnelDownStreamPayload(f->node, line, estBytes(line, "Y", 1));
    tunnelDownStreamFin(f->node, line);
    twfRequire(lineIsAlive(line), "downstream Finish discarded a nested accepted reply");
}

static void finishDrainsAcceptedReplies(void)
{
    for (unsigned nested_payload = 0; nested_payload < 2; ++nested_payload)
    {
        est_fixture_t f;
        setup(&f, 1000);
        sendRequest(&f, false);
        terminal_handoffs = 0;
        f.next->fnPauseU  = countNextPermission;
        f.next->fnResumeU = countNextPermission;
        if (nested_payload)
        {
            f.on_down = queueReplyThenFinishFromPayload;
            tunnelDownStreamPayload(f.node, f.line, estBytes(f.line, "X", 1));
        }
        else
        {
            f.on_down = terminalPressure;
            f.on_est  = queueReplyThenFinishFromEst;
            tunnelDownStreamEst(f.node, f.line);
        }
        twfRequire(! lineIsAlive(f.line), "deferred downstream Finish left its carrier alive");
        twfRequire(f.up_finish_count == 0 && f.down_finish_count == 1,
                   "deferred Finish reflected or closed the owner more than once");
        twfRequire(f.pause_count == 0 && f.up_len == 0, "deferred close or EOF handoff called the finished next side");
        twfRequire(terminal_handoffs == 1, "deferred Finish did not emit exactly one terminal frame");
        verifyResponse(&f, (const uint8_t *) "XY", nested_payload ? 2 : 1, true);
        closeFixture(&f);
    }
}

static void authenticationDeadlineAndCancellation(void)
{
    est_fixture_t f;
    setup(&f, 10);
    twfRequireEqualU32(twfLineRefCount(f.line), 3, "pending authentication did not retain its line");
    sendBytes(&f, vector_request, 15);
    const uint64_t end = getHRTimeUs() + 500000;
    while (lineIsAlive(f.line) && getHRTimeUs() < end)
        discard wloopProcessEvents(f.env.loop, 1);
    twfRequire(! lineIsAlive(f.line) && f.init_count == 0, "incomplete AuthID escaped handshake deadline");
    twfRequireEqualU32(twfLineRefCount(f.line), 1, "expired authentication retained its line");
    closeFixture(&f);

    setup(&f, 1000);
    sendBytes(&f, vector_request, 16);
    tunnelUpStreamFin(f.node, f.line);
    lineDestroy(f.line);
    pump(&f, 10);
    twfRequire(f.init_count == 0 && f.down_finish_count == 0, "canceled auth reopened or reflected Finish");
    closeFixture(&f);
}

static void authenticationRefreshWithBudget(size_t cache_bytes)
{
    est_fixture_t f;
    setup(&f, 1000);
    users_t users;
    twfRequire(usersCreate(&users), "managed snapshot table creation failed");
    user_t user;
    twfRequire(userCreate(&user, "ffffffff-ffff-ffff-ffff-ffffffffffff"), "initial UUID construction failed");
    userSetId(&user, 1);
    twfRequire(usersAddUser(&users, &user), "initial UUID insertion failed");
    userDestroy(&user);
    tunnel_t *auth = tunnelCreate(NULL, sizeof(authenticationclient_tstate_t), 0);
    twfRequire(auth != NULL, "managed authentication fixture allocation failed");
    authenticationclient_tstate_t *state = tunnelGetState(auth);
    mutexInit(&state->control_mutex);
    rwlockinit(&state->users_lock);
    state->users            = &users;
    state->users_generation = 1;
    state->started = state->users_loaded = state->clock_loaded            = true;
    state->sync_max_users                                                 = 100000;
    state->sync_max_bytes                                                 = 268435456;
    usersLookupByIdentifier(&users, 1)->runtime.identity_generation_floor = 1;
    vmessserver_tstate_t *ts                                              = tunnelGetState(f.node);
    ts->auth_cache_max_bytes                                              = cache_bytes;
    ts->auth_client_tunnel                                                = auth;
    ts->fallback_tunnel                                                   = f.next;
    refresh_trials                                                        = 0;
    refresh_auth                                                          = auth;
    sendRequest(&f, false);
    vmessserver_lstate_t *ls = lineGetState(f.line, f.node);
    twfRequire(refresh_trials >= 3 && ls->phase != kVmessServerPhaseFallback && ls->user_handle.user_id == 42 &&
                   ls->user_handle.generation == 2,
               "a stale snapshot miss selected fallback instead of retrying the current users");
    twfRequireEqualU32(twfLineRefCount(f.line), 2, "authenticated line retained its pending job reference");
    refresh_auth = NULL;
    closeFixture(&f);
    usersDestroy(&users);
    rwlockDestroy(&state->users_lock);
    mutexDestroy(&state->control_mutex);
    tunnelDestroy(auth);
}

static void authenticationRefreshAfterMiss(void)
{
    authenticationRefreshWithBudget(4U * 1024U * 1024U);
}

static void authenticationRefreshWithTightCache(void)
{
    /* Each vector fits separately, but old and replacement cannot coexist. The
     * miss releases its pinned old vector before replacement allocation. */
    authenticationRefreshWithBudget(192);
}

static void fallbackSourceFinish(void)
{
    est_fixture_t f;
    setup(&f, 1000);
    vmessserver_tstate_t *ts          = tunnelGetState(f.node);
    ts->fallback_tunnel               = f.next;
    ts->fallback_intentional_delay_ms = 50;
    const uint8_t probe[]             = "invalid-vmess-authentication-prefix-and-body";
    sendBytes(&f, probe, sizeof(probe) - 1);
    waitInitialized(&f);
    twfRequire(((vmessserver_lstate_t *) lineGetState(f.line, f.node))->phase == kVmessServerPhaseFallback,
               "unknown AuthID did not select fallback");
    tunnelUpStreamFin(f.node, f.line);
    lineDestroy(f.line);
    twfRequire(f.up_len == sizeof(probe) - 1 && memoryCompare(f.up, probe, sizeof(probe) - 1) == 0,
               "source Finish lost delayed fallback prefix or body");
    twfRequire(f.up_finish_count == 1 && f.down_finish_count == 0, "fallback Finish direction changed");
    pump(&f, 60);
    closeFixture(&f);
}

static unsigned udp_deliveries;

static void recordUdpDelivery(est_fixture_t *fixture, line_t *line)
{
    discard fixture;
    discard line;
    ++udp_deliveries;
}

static void udpBackendRecreation(void)
{
    est_fixture_t f;
    setup(&f, 1000);
    udp_deliveries = 0;
    f.on_up        = recordUdpDelivery;
    sendRequest(&f, true);
    sendBytes(&f, vector_frame_3_13_0, sizeof(vector_frame_3_13_0));
    vmessserver_lstate_t *ls      = lineGetState(f.line, f.node);
    line_t               *backend = ls->udp_remote_line;
    twfRequire(backend != NULL && f.up_len == 11, "UDP backend missing first datagram");
    lineRef(backend);
    tunnelDownStreamFin(f.node, backend);
    twfRequire(! lineIsAlive(backend) && lineIsAlive(f.line), "UDP backend close killed wrong exact line");
    lineUnref(backend);
    sendBytes(&f, vector_frame_3_13_1, sizeof(vector_frame_3_13_1));
    twfRequire(f.init_count == 2 && f.up_len == 42, "UDP backend recreation lost next datagram");
    sendBytes(&f, vector_frame_3_13_2, sizeof(vector_frame_3_13_2));
    twfRequire(! lineIsAlive(f.line) && udp_deliveries == 2,
               "authenticated UDP termination was forwarded as an empty datagram");
    closeFixture(&f);
}

static void overflowResponses(est_fixture_t *f, line_t *line)
{
    f->on_est = NULL;
    for (unsigned i = 0; i <= kVmessServerMaxPendingBuffers && lineIsAlive(line); ++i)
        tunnelDownStreamPayload(f->node, line, estBytes(line, "X", 1));
}

static void queuedResponseLimit(void)
{
    est_fixture_t f;
    setup(&f, 1000);
    sendRequest(&f, false);
    f.on_est = overflowResponses;
    tunnelDownStreamEst(f.node, f.line);
    twfRequire(! lineIsAlive(f.line), "reentrant response queue exceeded its entry limit");
    twfRequire(f.up_finish_count == 1 && f.down_finish_count == 1, "queue refusal did not close both directions");
    closeFixture(&f);
}

int main(void)
{
    initWLibc();
    logger_t *logger = loggerCreate();
    twfRequire(logger != NULL, "logger creation failed");
    loggerSetLevel(logger, LOG_LEVEL_ERROR);
    setNetworkLogger(logger);
    twfRequire(globalstateInitializeSecureRandom(), "secure random initialization failed");
    twfRequire(frandGlobalInit(), "fast random initialization failed");
    frandInit();
    twfRequire(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");
    TEST_RUN_CASE(splitParser);
    TEST_RUN_CASE(reentrantInitAndResponse);
    TEST_RUN_CASE(closeDuringResponseDelivery);
    TEST_RUN_CASE(finishDrainsAcceptedReplies);
    TEST_RUN_CASE(authenticationDeadlineAndCancellation);
    TEST_RUN_CASE(authenticationRefreshAfterMiss);
    TEST_RUN_CASE(authenticationRefreshWithTightCache);
    TEST_RUN_CASE(fallbackSourceFinish);
    TEST_RUN_CASE(udpBackendRecreation);
    TEST_RUN_CASE(queuedResponseLimit);
    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    networkloggerDestroy();
    return 0;
}
