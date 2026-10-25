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
    ts->users[0].username           = stringDuplicate("vmess-fixture");
    ts->user_count                  = 1;
    ts->allow_connect               = true;
    ts->allow_udp                   = true;
    ts->allowed_security            = 15;
    ts->send_termination            = true;
    ts->packetaddr                  = true;
    ts->packetaddr_max_destinations = 2;
    ts->owned_backends              = memoryAllocateZero(sizeof(*ts->owned_backends));
    ts->handshake_timeout_ms        = timeout_ms;
    ts->auth_max_pending            = 8;
    ts->auth_pending_max_bytes      = 4U * 1024U * 1024U;
    ts->auth_cache_max_bytes        = 4U * 1024U * 1024U;
    ts->replay_max_entries          = 64;
    ts->replay                      = vmessReplayCreate(ts->replay_max_entries);
    ts->auth                        = vmessserverAuthCreate(f->node);
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
    twfRequire(ts->owned_backends[0] == NULL, "owned backend survives shutdown");
    memoryFree(ts->owned_backends);
    nodeApiUnregister(f->node);
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

static void verifyResponseAtCounter(est_fixture_t *f, const uint8_t *expected, size_t size, bool expected_eof,
                                    uint32_t counter)
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
                             false,
                             kVmessCounterWrap) == kWCryptoOk,
               "response decoder failed");
    decoder.counter = counter;
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

static void verifyResponse(est_fixture_t *f, const uint8_t *expected, size_t size, bool expected_eof)
{
    verifyResponseAtCounter(f, expected, size, expected_eof, 0);
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

static void customRequest(est_fixture_t *f, uint8_t security, uint8_t options, bool udp, bool packetaddr)
{
    vmess_request_header_t request = {.version        = 1,
                                      .command        = udp ? 2 : 1,
                                      .security       = security,
                                      .options        = options,
                                      .response       = 42,
                                      .address_type   = 1,
                                      .address_length = 4,
                                      .port           = 4242,
                                      .address        = {127, 0, 0, 1}};
    memoryCopy(request.key, vector_key, 16);
    memoryCopy(request.iv, vector_iv, 16);
    if (packetaddr)
    {
        static const char marker[] = "sp.packet-addr.v2fly.arpa";
        request.address_type       = 2;
        request.address_length     = sizeof(marker) - 1;
        request.port               = 0;
        memoryCopy(request.address, marker, sizeof(marker) - 1);
    }
    vmess_prepared_key_t prepared;
    twfRequire(vmessPrepareKey(vector_uuid, &prepared) == kWCryptoOk, "custom key");
    uint8_t auth[16], random[4] = {1, 2, 3, 4}, nonce[8] = {0}, wire[512];
    size_t  length;
    twfRequire(vmessAuthIdCreate(&prepared, 1700000000, random, auth) == kWCryptoOk, "custom authid");
    twfRequire(vmessRequestHeaderSeal(prepared.cmd_key, auth, nonce, &request, NULL, 0, wire, sizeof(wire), &length) ==
                   kWCryptoOk,
               "custom header");
    sendBytes(f, wire, length);
    const uint64_t end = getHRTimeUs() + 1000000;
    while (lineIsAlive(f->line) &&
           ((vmessserver_lstate_t *) lineGetState(f->line, f->node))->phase == kVmessServerPhaseWaitInitial &&
           getHRTimeUs() < end)
        discard wloopProcessEvents(f->env.loop, 1);
}

static void sealSend(est_fixture_t *f, vmess_body_ctx_t *sender, const void *bytes, size_t size)
{
    uint8_t wire[1024];
    size_t  length;
    twfRequire(vmessBodySeal(sender, bytes, size, false, wire, sizeof(wire), &length) == kWCryptoOk, "runtime seal");
    sendBytes(f, wire, length);
}

static void serverCounterWrap(void)
{
    const uint8_t modes[] = {VMESS_SECURITY_AES128_GCM, VMESS_SECURITY_CHACHA20_POLY1305};
    for (size_t m = 0; m < 2; ++m)
        for (unsigned udp = 0; udp < 2; ++udp)
        {
            est_fixture_t f;
            setup(&f, 1000);
            customRequest(&f, modes[m], 29, udp, false);
            twfRequire(lineIsAlive(f.line) && f.init_count == 1, "wrap request rejected");
            vmess_body_ctx_t tx = {0}, rx = {0};
            uint8_t          key[16], iv[16];
            twfRequire(vmessResponseKeys(vector_key, vector_iv, key, iv) == kWCryptoOk, "wrap keys");
            twfRequire(vmessBodyInit(&tx, vector_key, vector_iv, modes[m], 29, udp ? 2 : 1, true, kVmessCounterWrap) ==
                               kWCryptoOk &&
                           vmessBodyInit(&rx, key, iv, modes[m], 29, udp ? 2 : 1, false, kVmessCounterWrap) ==
                               kWCryptoOk &&
                           vmessBodySetLengthMaterial(&rx, vector_key, vector_iv) == kWCryptoOk,
                       "wrap contexts");
            for (uint32_t i = 0; i < 131074; ++i)
            {
                uint8_t data = (uint8_t) i;
                f.up_len = f.down_len = 0;
                sealSend(&f, &tx, &data, 1);
                twfRequire(lineIsAlive(f.line) && f.up_len == 1 && f.up[0] == data,
                           "server RX closed early or changed record at wrap");
                vmessserver_lstate_t *ls      = lineGetState(f.line, f.node);
                line_t               *backend = udp ? ls->udp_remote_line : f.line;
                tunnelDownStreamPayload(f.node, backend, estBytes(backend, &data, 1));
                twfRequire(lineIsAlive(f.line), "server TX closed at wrap");
                size_t   prefix = i == 0 ? VMESS_RESPONSE_HEADER_SIZE : 0;
                uint32_t body;
                twfRequire(vmessBodyLengthOpen(&rx, f.down + prefix, vmessBodyLengthSize(&rx), &body) == kWCryptoOk,
                           "response length discontinuity");
                prefix += vmessBodyLengthSize(&rx);
                uint8_t actual[128];
                size_t  count;
                bool    eof;
                twfRequire(f.down_len == prefix + body &&
                               vmessBodyOpen(&rx, f.down + prefix, body, actual, sizeof(actual), &count, &eof) ==
                                   kWCryptoOk &&
                               count == 1 && actual[0] == data && ! eof,
                           "response body discontinuity");
            }
            vmessserver_tstate_t *ts = tunnelGetState(f.node);
            twfRequire(atomic_load(&ts->stats.wrap_events) == 4, "wrap events not published independently");
            vmessBodyDestroy(&tx);
            vmessBodyDestroy(&rx);
            closeFixture(&f);
        }
}

static void deniedSecurityAndTermination(void)
{
    est_fixture_t f;
    setup(&f, 1000);
    vmessserver_tstate_t *ts = tunnelGetState(f.node);
    ts->allowed_security     = 4;
    customRequest(&f, VMESS_SECURITY_AES128_GCM, 13, false, false);
    twfRequire(! lineIsAlive(f.line) && f.init_count == 0 &&
                   atomic_load(&ts->stats.reasons[kVmessServerReasonSecurityDenied]) == 1,
               "denied authenticated security reached protected Init");
    closeFixture(&f);
    for (unsigned termination = 0; termination < 2; ++termination)
    {
        setup(&f, 1000);
        ts                   = tunnelGetState(f.node);
        ts->send_termination = termination;
        sendRequest(&f, false);
        tunnelDownStreamPayload(f.node, f.line, estBytes(f.line, "A", 1));
        size_t size = f.down_len;
        tunnelDownStreamFin(f.node, f.line);
        twfRequire(! lineIsAlive(f.line) && (f.down_len > size) == (bool) termination,
                   "server termination selection ignored");
        closeFixture(&f);
    }
    setup(&f, 1000);
    ts                 = tunnelGetState(f.node);
    ts->counter_policy = kVmessCounterStrict;
    sendRequest(&f, false);
    vmessserver_lstate_t *ls  = lineGetState(f.line, f.node);
    ls->output_crypto.counter = 65534;
    tunnelDownStreamPayload(f.node, f.line, estBytes(f.line, "A", 1));
    twfRequire(lineIsAlive(f.line) && ls->output_crypto.counter == 65535, "strict final data lost");
    tunnelDownStreamPayload(f.node, f.line, estBytes(f.line, "B", 1));
    twfRequire(! lineIsAlive(f.line) && atomic_load(&ts->stats.strict_exhaustion) == 1,
               "server strict output reused nonce");
    closeFixture(&f);
}

static void sendPacket(est_fixture_t *f, vmess_body_ctx_t *tx, unsigned destination, bool ipv6, bool empty)
{
    vmess_packet_addr_t address    = {.address_type = ipv6 ? 3 : 1, .port = (uint16_t) (4242 + destination)};
    address.address[ipv6 ? 15 : 3] = (uint8_t) (destination + 1);
    if (! ipv6)
        address.address[0] = 127;
    uint8_t data[32];
    size_t  prefix;
    twfRequire(vmessPacketAddrEncode(&address, data, sizeof(data), &prefix) == kWCryptoOk, "packet envelope");
    data[prefix] = (uint8_t) destination;
    sealSend(f, tx, data, prefix + ! empty);
}

static void verifyPacketReplies(est_fixture_t *f, bool ipv6, const unsigned *destinations, const char *const *payloads,
                                size_t count)
{
    twfRequire(f->down_len >= VMESS_RESPONSE_HEADER_SIZE, "packetaddr response header missing");
    uint16_t length = 0;
    twfRequire(vmessResponseLengthOpen(vector_response_key, vector_response_iv, f->down, &length) == kWCryptoOk &&
                   length == 4 &&
                   vmessResponseHeaderOpen(vector_response_key, vector_response_iv, 42, f->down + 18, 20) == kWCryptoOk,
               "packetaddr response header authentication failed");
    vmess_body_ctx_t rx = {0};
    twfRequire(vmessBodyInit(&rx, vector_response_key, vector_response_iv, 3, 13, 2, false, kVmessCounterWrap) ==
                   kWCryptoOk,
               "packetaddr reply decoder initialization failed");
    size_t cursor = VMESS_RESPONSE_HEADER_SIZE;
    for (size_t index = 0; index < count; ++index)
    {
        uint32_t body_length = 0;
        size_t   prefix      = vmessBodyLengthSize(&rx);
        twfRequire(cursor <= f->down_len && prefix <= f->down_len - cursor &&
                       vmessBodyLengthOpen(&rx, f->down + cursor, prefix, &body_length) == kWCryptoOk,
                   "packetaddr reply length invalid");
        cursor += prefix;
        uint8_t plain[128];
        size_t  plain_length = 0;
        bool    eof          = false;
        twfRequire(body_length <= f->down_len - cursor &&
                       vmessBodyOpen(&rx, f->down + cursor, body_length, plain, sizeof(plain), &plain_length, &eof) ==
                           kWCryptoOk &&
                       ! eof,
                   "packetaddr reply body invalid");
        cursor += body_length;
        vmess_packet_addr_t address;
        size_t              envelope = 0;
        twfRequire(vmessPacketAddrDecode(plain, plain_length, &address, &envelope) == kWCryptoOk &&
                       address.address_type == (ipv6 ? 3 : 1) && address.port == 4242 + destinations[index],
                   "packetaddr reply lost immutable family/port");
        uint8_t expected_ip[16]    = {0};
        expected_ip[ipv6 ? 15 : 3] = (uint8_t) (destinations[index] + 1);
        if (! ipv6)
            expected_ip[0] = 127;
        twfRequire(memoryEqual(address.address, expected_ip, ipv6 ? 16 : 4), "packetaddr reply lost immutable IP");
        size_t payload_length = strlen(payloads[index]);
        twfRequire(plain_length == envelope + payload_length &&
                       memoryEqual(plain + envelope, payloads[index], payload_length),
                   "packetaddr reply changed datagram bytes/boundary");
    }
    twfRequire(cursor == f->down_len, "packetaddr reply stream has unexpected records");
    vmessBodyDestroy(&rx);
}

static void packetaddrDeniedBeforeTable(void)
{
    est_fixture_t f;
    setup(&f, 1000);
    vmessserver_tstate_t *ts = tunnelGetState(f.node);
    ts->packetaddr           = false;
    customRequest(&f, VMESS_SECURITY_AES128_GCM, 13, true, true);
    twfRequire(! lineIsAlive(f.line) && f.init_count == 0 && f.est_count == 0 &&
                   atomicLoadU64Relaxed(&ts->stats.reasons[kVmessServerReasonCommandDenied]) == 1 &&
                   ts->owned_backends[0] == NULL,
               "denied packetaddr request did not settle before table/backend creation");
    closeFixture(&f);
}

static void packetaddrReplayBeforeTable(void)
{
    est_fixture_t f;
    setup(&f, 1000);
    vmessserver_tstate_t *ts = tunnelGetState(f.node);
    vmess_prepared_key_t  key;
    uint8_t               auth[16], random[4] = {1, 2, 3, 4};
    twfRequire(
        vmessPrepareKey(vector_uuid, &key) == kWCryptoOk &&
            vmessAuthIdCreate(&key, 1700000000, random, auth) == kWCryptoOk &&
            vmessReplayAdmit(
                ts->replay, auth, vector_uuid, vector_key, vector_iv, 1700000000, 1700000000, getHRTimeUs() / 1000U),
        "packetaddr replay refusal setup failed");
    memorySecureZero(&key, sizeof(key));
    customRequest(&f, VMESS_SECURITY_AES128_GCM, 13, true, true);
    twfRequire(! lineIsAlive(f.line) && f.init_count == 0 && f.est_count == 0 &&
                   atomicLoadU64Relaxed(&ts->stats.reasons[kVmessServerReasonReplayOrCapacity]) == 1 &&
                   ts->owned_backends[0] == NULL,
               "replayed packetaddr request did not settle before table/backend creation");
    closeFixture(&f);
}

static void packetaddrBackends(void)
{
    for (unsigned ipv6 = 0; ipv6 < 2; ++ipv6)
    {
        est_fixture_t f;
        setup(&f, 1000);
        customRequest(&f, VMESS_SECURITY_AES128_GCM, 13, true, true);
        twfRequire(f.init_count == 0 && f.est_count == 1, "magic target leaked to backend");
        vmess_body_ctx_t tx = {0};
        twfRequire(
            vmessBodyInit(&tx, vector_key, vector_iv, VMESS_SECURITY_AES128_GCM, 13, 2, true, kVmessCounterWrap) ==
                kWCryptoOk,
            "packet sender");
        sendPacket(&f, &tx, 0, ipv6, true);
        sendPacket(&f, &tx, 1, ipv6, false);
        vmessserver_lstate_t *ls = lineGetState(f.line, f.node);
        twfRequire(ls->udp_destination_count == 2 && f.init_count == 2 && f.up_len == 1,
                   "packetaddr lost empty datagram or destination separation");
        line_t *a = ls->udp_destinations[0], *b = ls->udp_destinations[1];
        twfRequire(lineGetAuthenticatedPassword(a) != NULL, "packetaddr lost authenticated identity");
        sendPacket(&f, &tx, 2, ipv6, false);
        vmessserver_tstate_t *ts = tunnelGetState(f.node);
        twfRequire(f.init_count == 2 && lineIsAlive(f.line) &&
                       atomic_load(&ts->stats.reasons[kVmessServerReasonDestinationCapacity]) == 1,
                   "packetaddr destination capacity closed established destinations");
        /* Replies borrow immutable backend targets even after a connector has
         * replaced its destination context. They queue independent owned bytes. */
        addresscontextSetPort(lineGetDestinationAddressContext(b), 9999);
        tunnelDownStreamPayload(f.node, b, estBytes(b, "B", 1));
        tunnelDownStreamPayload(f.node, a, estBytes(a, "", 0));
        twfRequire(f.down_len > VMESS_RESPONSE_HEADER_SIZE, "packetaddr reply/empty datagram absent");
        const unsigned    destinations[] = {1, 0};
        const char *const payloads[]     = {"B", ""};
        verifyPacketReplies(&f, ipv6, destinations, payloads, ARRAY_SIZE(destinations));
        twfRequire(atomic_load(&ts->stats.rx_application_bytes) == 1 &&
                       atomic_load(&ts->stats.tx_application_bytes) == 1,
                   "packetaddr counted envelopes as application bytes");
        lineRef(a);
        tunnelDownStreamFin(f.node, a);
        twfRequire(! lineIsAlive(a) && ls->udp_destination_count == 1 && lineIsAlive(f.line),
                   "backend Finish retained entry or killed carrier");
        lineUnref(a);
        sendPacket(&f, &tx, 0, ipv6, false);
        twfRequire(f.init_count == 3 && ls->udp_destination_count == 2, "backend not recreated");
        vmessBodyDestroy(&tx);
        closeFixture(&f);
    }
}

static line_t  *observed_backends[2];
static unsigned nested_calls;

static void packetSetup(est_fixture_t *f, vmess_body_ctx_t *tx, unsigned destinations)
{
    setup(f, 1000);
    customRequest(f, 3, 13, true, true);
    twfRequire(vmessBodyInit(tx, vector_key, vector_iv, 3, 13, 2, true, kVmessCounterWrap) == kWCryptoOk,
               "packetaddr runtime sender initialization failed");
    for (unsigned index = 0; index < destinations; ++index)
        sendPacket(f, tx, index, false, false);
    vmessserver_lstate_t *ls = lineGetState(f->line, f->node);
    for (unsigned index = 0; index < destinations; ++index)
    {
        observed_backends[index] = ls->udp_destinations[index];
        lineRef(observed_backends[index]);
    }
}

static void releaseObservedBackend(est_fixture_t *f, unsigned index)
{
    line_t *backend = observed_backends[index];
    twfRequire(backend != NULL && ! lineIsAlive(backend), "owned backend survives callback/owner drain");
    twfRequireLineStateZeroed(backend, f->node, "owned backend retains state after close");
    twfRequireEqualU32(twfLineRefCount(backend), 1, "owned backend leaked an association/callback reference");
    lineUnref(backend);
    observed_backends[index] = NULL;
}

static void parentFinishFromBackend(est_fixture_t *f, line_t *backend)
{
    f->on_init = f->on_up = NULL;
    observed_backends[0]  = backend;
    lineRef(backend);
    tunnelUpStreamFin(f->node, f->line);
    lineDestroy(f->line); /* The mock source owns the borrowed carrier. */
    twfRequire(! lineIsAlive(backend), "parent Finish returned with its owned backend alive");
}

static void packetaddrParentFinish(void)
{
    for (unsigned during_payload = 0; during_payload < 2; ++during_payload)
    {
        est_fixture_t    f;
        vmess_body_ctx_t tx = {0};
        packetSetup(&f, &tx, 0);
        if (during_payload)
            f.on_up = parentFinishFromBackend;
        else
            f.on_init = parentFinishFromBackend;
        sendPacket(&f, &tx, 0, false, false);
        twfRequire(! lineIsAlive(f.line) && f.down_finish_count == 0 && f.up_finish_count == 1 &&
                       f.up_len == during_payload,
                   "parent Finish during backend callback reflected or delivered after close");
        releaseObservedBackend(&f, 0);
        vmessBodyDestroy(&tx);
        closeFixture(&f);
    }
}

static void failBackendInit(est_fixture_t *f, line_t *backend)
{
    f->on_init = NULL;
    twfRequire(lineGetRoutingContext(backend)->local_listener_port == 8443 &&
                   lineGetSourceAddressContext(backend)->port == 1357 && lineGetAuthenticatedPassword(backend) != NULL,
               "packetaddr protected Init missed source/listener/authenticated context");
    observed_backends[0] = backend;
    lineRef(backend);
    tunnelDownStreamFin(f->node, backend);
    twfRequire(! lineIsAlive(backend), "failed backend Init returned with owned line alive");
}

static void packetaddrFailedInit(void)
{
    est_fixture_t    f;
    vmess_body_ctx_t tx = {0};
    packetSetup(&f, &tx, 0);
    lineGetRoutingContext(f.line)->local_listener_port = 8443;
    addresscontextSetPort(lineGetSourceAddressContext(f.line), 1357);
    f.on_init = failBackendInit;
    sendPacket(&f, &tx, 0, false, false);
    vmessserver_lstate_t *ls = lineGetState(f.line, f.node);
    twfRequire(lineIsAlive(f.line) && ls->udp_destination_count == 0 && f.up_len == 0 && f.init_count == 1,
               "failed packetaddr backend Init killed carrier or retained entry/payload");
    sendPacket(&f, &tx, 0, false, false);
    twfRequire(lineIsAlive(f.line) && f.init_count == 2 && ls->udp_destination_count == 1 && f.up_len == 1 &&
                   ls->udp_destinations[0] != observed_backends[0],
               "failed packetaddr backend was not recreated independently");
    releaseObservedBackend(&f, 0);
    vmessBodyDestroy(&tx);
    closeFixture(&f);
}

static void closeBackendsFromPermission(tunnel_t *t, line_t *backend)
{
    est_fixture_t *f = estContext(t);
    ++nested_calls;
    twfRequire(backend == observed_backends[0], "permission notified a retired sibling");
    tunnelDownStreamFin(f->node, observed_backends[1]);
    tunnelDownStreamFin(f->node, backend);
    tunnelUpStreamResume(f->node, f->line); /* Reenters the permission dispatcher. */
}

static void finishParentFromPermission(tunnel_t *t, line_t *backend)
{
    est_fixture_t *f = estContext(t);
    discard        backend;
    ++nested_calls;
    tunnelUpStreamFin(f->node, f->line);
    lineDestroy(f->line);
}

static void packetaddrPermissionReentry(void)
{
    for (unsigned finish_parent = 0; finish_parent < 2; ++finish_parent)
    {
        est_fixture_t    f;
        vmess_body_ctx_t tx = {0};
        packetSetup(&f, &tx, 2);
        nested_calls     = 0;
        f.next->fnPauseU = finish_parent ? finishParentFromPermission : closeBackendsFromPermission;
        tunnelUpStreamPause(f.node, f.line);
        twfRequire(nested_calls == 1 && lineIsAlive(f.line) == ! finish_parent,
                   "permission dispatcher reused retired backend/carrier state");
        if (! finish_parent)
        {
            vmessserver_lstate_t *ls = lineGetState(f.line, f.node);
            twfRequire(ls->udp_destination_count == 0 && ! ls->response_paused && ! ls->permission_dispatching,
                       "nested backend closure stranded permission dispatcher");
        }
        releaseObservedBackend(&f, 0);
        releaseObservedBackend(&f, 1);
        vmessBodyDestroy(&tx);
        closeFixture(&f);
    }
}

static uint8_t closing_input[128];
static size_t  closing_input_length;

static void siblingFinishDuringDrain(tunnel_t *t, line_t *backend)
{
    est_fixture_t *f = estContext(t);
    ++f->up_finish_count;
    ++nested_calls;
    twfRequire(nested_calls == 1 && backend == observed_backends[0], "owner drain revisited retired backend");
    twfRequireLineStateZeroed(backend, f->node, "backend state survived outward Finish");
    tunnelDownStreamFin(f->node, observed_backends[1]);
    sendBytes(f, closing_input, closing_input_length);
    tunnelUpStreamFin(f->node, f->line);
    lineDestroy(f->line);
}

static void packetaddrDrainReentry(void)
{
    est_fixture_t    f;
    vmess_body_ctx_t tx = {0};
    packetSetup(&f, &tx, 2);
    uint8_t envelope[] = {1, 127, 0, 0, 3, 0x10, 0x94, 'X'};
    twfRequire(
        vmessBodySeal(
            &tx, envelope, sizeof(envelope), false, closing_input, sizeof(closing_input), &closing_input_length) ==
            kWCryptoOk,
        "closing input seal failed");
    nested_calls   = 0;
    f.next->fnFinU = siblingFinishDuringDrain;
    tunnelUpStreamFin(f.node, f.line);
    twfRequire(! lineIsAlive(f.line) && nested_calls == 1 && f.init_count == 2 && f.up_len == 2 &&
                   ((vmessserver_tstate_t *) tunnelGetState(f.node))->owned_backends[0] == NULL,
               "reentrant owner drain admitted another backend or leaked ownership");
    releaseObservedBackend(&f, 0);
    releaseObservedBackend(&f, 1);
    vmessBodyDestroy(&tx);
    closeFixture(&f);
}

static void destroyParentBeforeSiblingFinish(tunnel_t *t, line_t *backend)
{
    est_fixture_t *f = estContext(t);
    ++f->up_finish_count;
    twfRequire(nested_calls < 2 && backend == observed_backends[nested_calls],
               "owner drain revisited a retired backend after parent death");
    ++nested_calls;
    twfRequireLineStateZeroed(backend, f->node, "backend retains resources during outward Finish");
    if (nested_calls == 1)
    {
        twfRequire(lineIsAlive(observed_backends[1]), "sibling retired before parent-death trigger");
        tunnelUpStreamFin(f->node, f->line);
        lineDestroy(f->line);
        twfRequire(! lineIsAlive(f->line) && lineIsAlive(observed_backends[1]),
                   "parent was not destroyed before remaining backend retirement");
    }
    else
        twfRequire(! lineIsAlive(f->line), "remaining backend drained before parent logical death");
}

static void packetaddrParentDiesDuringDrain(void)
{
    est_fixture_t    f;
    vmess_body_ctx_t tx = {0};
    packetSetup(&f, &tx, 2);
    nested_calls   = 0;
    f.next->fnFinU = destroyParentBeforeSiblingFinish;
    tunnelUpStreamFin(f.node, f.line);
    twfRequire(! lineIsAlive(f.line) && nested_calls == 2 && f.init_count == 2 &&
                   ((vmessserver_tstate_t *) tunnelGetState(f.node))->owned_backends[0] == NULL,
               "parent logical death interrupted complete owned-backend drain");
    releaseObservedBackend(&f, 0);
    releaseObservedBackend(&f, 1);
    vmessBodyDestroy(&tx);
    closeFixture(&f);
}

static void queueReplyAndRetireBackend(est_fixture_t *f, line_t *carrier)
{
    discard carrier;
    f->on_down      = NULL;
    line_t *backend = observed_backends[0];
    tunnelDownStreamPayload(f->node, backend, estBytes(backend, "queued", 6));
    tunnelDownStreamFin(f->node, backend);
    twfRequire(! lineIsAlive(backend) &&
                   bufferqueueGetBufCount(&((vmessserver_lstate_t *) lineGetState(f->line, f->node))->pending_down) ==
                       1,
               "backend death discarded independently queued reply");
}

static void packetaddrQueuedReplyOwnership(void)
{
    est_fixture_t    f;
    vmess_body_ctx_t tx = {0};
    packetSetup(&f, &tx, 2);
    addresscontextSetPort(lineGetDestinationAddressContext(observed_backends[0]), 9999);
    f.on_down = queueReplyAndRetireBackend;
    tunnelDownStreamPayload(f.node, observed_backends[1], estBytes(observed_backends[1], "first", 5));
    const unsigned    destinations[] = {1, 0};
    const char *const payloads[]     = {"first", "queued"};
    verifyPacketReplies(&f, false, destinations, payloads, ARRAY_SIZE(destinations));
    twfRequire(lineIsAlive(f.line) &&
                   ((vmessserver_lstate_t *) lineGetState(f.line, f.node))->udp_destination_count == 1,
               "queued reply retirement killed carrier or retained map entry");
    releaseObservedBackend(&f, 0);
    vmessBodyDestroy(&tx);
    tunnelUpStreamFin(f.node, f.line);
    lineDestroy(f.line);
    releaseObservedBackend(&f, 1);
    closeFixture(&f);
}

static void serverStrictReceive(void)
{
    for (unsigned udp = 0; udp < 2; ++udp)
        for (uint8_t security = 3; security <= 4; ++security)
        {
            est_fixture_t f;
            setup(&f, 1000);
            vmessserver_tstate_t *ts = tunnelGetState(f.node);
            ts->counter_policy       = kVmessCounterStrict;
            customRequest(&f, security, 29, udp, false);
            vmessserver_lstate_t *ls = lineGetState(f.line, f.node);
            ls->input_crypto.counter = UINT16_MAX;
            vmess_body_ctx_t tx      = {0};
            twfRequire(vmessBodyInit(&tx, vector_key, vector_iv, security, 29, udp ? 2 : 1, true, kVmessCounterWrap) ==
                           kWCryptoOk,
                       "strict RX peer initialization failed");
            tx.counter = UINT16_MAX;
            uint8_t wire[256];
            size_t  first = 0, second = 0;
            twfRequire(
                vmessBodySeal(&tx, (const uint8_t *) "A", 1, false, wire, sizeof(wire), &first) == kWCryptoOk &&
                    vmessBodySeal(&tx, (const uint8_t *) "B", 1, false, wire + first, sizeof(wire) - first, &second) ==
                        kWCryptoOk,
                "strict RX boundary frames failed");
            sendBytes(&f, wire, first + second);
            twfRequire(
                ! lineIsAlive(f.line) && f.up_len == 1 && f.up[0] == 'A' && atomic_load(&ts->stats.rx_records) == 1 &&
                    atomic_load(&ts->stats.rx_application_bytes) == 1 && atomic_load(&ts->stats.strict_exhaustion) == 1,
                "strict RX lost final valid data or delivered reused nonce");
            vmessBodyDestroy(&tx);
            closeFixture(&f);
        }
}

static void finishCarrierDuringTerminal(est_fixture_t *f, line_t *line)
{
    vmessserver_lstate_t *ls = lineGetState(line, f->node);
    if (! ls->output_crypto.ended)
        return;
    ++terminal_handoffs;
    tunnelUpStreamPause(f->node, line);
    tunnelUpStreamResume(f->node, line);
    tunnelUpStreamFin(f->node, line);
    if (lineIsAlive(line))
        lineDestroy(line);
}

static void nestedFinishWithQueuedReply(est_fixture_t *f, line_t *line)
{
    f->on_down = finishCarrierDuringTerminal;
    tunnelDownStreamPayload(f->node, line, estBytes(line, "Y", 1));
    tunnelDownStreamFin(f->node, line);
    twfRequire(lineIsAlive(line), "nested Finish discarded an accepted pending reply");
}

static void serverTerminationReentry(void)
{
    for (unsigned strict = 0; strict < 2; ++strict)
        for (unsigned termination = 0; termination < 2; ++termination)
        {
            est_fixture_t f;
            setup(&f, 1000);
            vmessserver_tstate_t *ts = tunnelGetState(f.node);
            ts->send_termination     = termination;
            ts->counter_policy       = strict ? kVmessCounterStrict : kVmessCounterWrap;
            sendRequest(&f, false);
            vmessserver_lstate_t *ls = lineGetState(f.line, f.node);
            if (strict)
                ls->output_crypto.counter = UINT16_MAX - 1;
            terminal_handoffs = 0;
            f.next->fnPauseU = f.next->fnResumeU = countNextPermission;
            f.on_down                            = nestedFinishWithQueuedReply;
            tunnelDownStreamPayload(f.node, f.line, estBytes(f.line, "X", 1));
            twfRequire(! lineIsAlive(f.line) && terminal_handoffs == termination && f.up_finish_count == 0 &&
                           f.down_finish_count == ! termination && f.pause_count == 0,
                       "termination selection/reentrant final handoff reflected callback or leaked line");
            verifyResponseAtCounter(
                &f, (const uint8_t *) "XY", strict ? 1 : 2, termination, strict ? UINT16_MAX - 1 : 0);
            twfRequire(atomic_load(&ts->stats.strict_exhaustion) == strict &&
                           atomic_load(&ts->stats.reasons[kVmessServerReasonStrictExhaustion]) == strict,
                       "strict exhaustion reason lost during reentrant final handoff");
            closeFixture(&f);
        }
}

static void serverConfiguration(void)
{
    const char *const cases[] = {
        "{\"uuid\":\"waterwall\"}",
        "{\"user-id\":\"waterwall\",\"encrypted-counter-policy\":\"strict\",\"allowed-security\":[\"none\"],\"send-"
        "termination\":false,\"packetaddr\":false,\"packetaddr-max-destinations\":1024}",
        "{\"users\":[\"waterwall\",\"106b9dde-356b-5769-b2f6-7ea4193ec5f7\"]}",
        "{\"uuid\":\"waterwall\\u0000suffix\"}",
        "{\"uuid\":\"1234567890123456789012345678901\"}",
        "{\"uuid\":\"waterwall\",\"send-termination\":1}",
        "{\"uuid\":\"waterwall\",\"send-termination\":true,\"send-termination\":false}",
        "{\"uuid\":\"waterwall\",\"packetaddr\":null}",
        "{\"uuid\":\"waterwall\",\"verbose\":\"true\"}",
        "{\"uuid\":\"waterwall\",\"packetaddr-max-destinations\":1.0}",
        "{\"uuid\":\"waterwall\",\"packetaddr-max-destinations\":0}",
        "{\"uuid\":\"waterwall\",\"packetaddr-max-destinations\":1025}",
        "{\"uuid\":\"waterwall\",\"encrypted-counter-policy\":\"wrap\\u0000strict\"}",
        "{\"uuid\":\"waterwall\",\"encrypted-counter-policy\":\"unknown\"}",
        "{\"uuid\":\"waterwall\",\"allowed-security\":[]}",
        "{\"uuid\":\"waterwall\",\"allowed-security\":[\"auto\"]}",
        "{\"uuid\":\"waterwall\",\"allowed-security\":[\"zero\",\"zero\"]}",
        "{\"uuid\":\"waterwall\",\"allowed-security\":[\"none\\u0000zero\"]}",
        "{\"uuid\":\"waterwall\",\"allowed-security\":[\"zero\"],\"connect\":false}",
        "{\"uuid\":\"waterwall\",\"id\":\"other\"}",
    };
    est_fixture_t f;
    setup(&f, 1000);
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        node_t node             = nodeVmessServerGet();
        node.next               = stringDuplicate("out");
        node.node_settings_json = cJSON_Parse(cases[i]);
        twfRequire(node.node_settings_json != NULL, "configuration fixture JSON");
        tunnel_t *t = vmessserverTunnelCreate(&node);
        twfRequire((t != NULL) == (i < 2), "server strict configuration acceptance");
        if (t != NULL)
        {
            vmessserver_tstate_t *ts = tunnelGetState(t);
            twfRequire(ts->counter_policy == (i == 0 ? kVmessCounterWrap : kVmessCounterStrict) &&
                           ts->send_termination == (i == 0) && ts->packetaddr == (i == 0),
                       "server effective defaults");
            vmessserverTunnelDestroy(t, wwLifecycleStartupRollback());
        }
        cJSON_Delete(node.node_settings_json);
        memoryFree(node.next);
        memoryFree(node.type);
    }
    closeFixture(&f);
}

static void serverStats(void)
{
    est_fixture_t f;
    setup(&f, 1000);
    twfRequire(vmessserverRegisterApi(f.node), "server API registration");
    const node_api_operation_t *op = nodeApiFind(f.node, "stats");
    twfRequire(op != NULL && op->read_only && op->execution == kNodeApiCallingWorker, "stats descriptor");
    node_api_call_context_t context = {.operation                = "stats",
                                       .deadline_ms              = nodeApiNowMs() + 10000,
                                       .max_response_body_size   = 4096,
                                       .working_memory_allowance = 16384};
    vmessserver_tstate_t   *ts      = tunnelGetState(f.node);
    atomicStoreU64Relaxed(&ts->stats.tx_wire_bytes, UINT64_MAX);
    api_result_t result = op->handler(f.node, estBytes(f.line, "{}", 2), &context);
    twfRequire(result.result_code == kApiResultOk && result.buffer != NULL, "registered server stats");
    char   text[4096];
    size_t size = sbufGetLength(result.buffer);
    twfRequire(size < sizeof(text), "stats result size");
    memoryCopy(text, sbufGetRawPtr(result.buffer), size);
    text[size]  = '\0';
    cJSON *body = cJSON_Parse(text);
    twfRequire(body != NULL && strcmp(cJSON_GetObjectItemCaseSensitive(body, "tx_wire_bytes")->valuestring,
                                      "18446744073709551615") == 0,
               "server stats uint64 precision");
    cJSON_Delete(body);
    lineReuseBuffer(f.line, result.buffer);
    const char *const bad[] = {"null", "[]", "{\"uuid\":\"secret\"}", "{} trailing", "{\"x\":1,\"x\":2}"};
    for (size_t i = 0; i < ARRAY_SIZE(bad); ++i)
    {
        result = op->handler(f.node, estBytes(f.line, bad[i], strlen(bad[i])), &context);
        twfRequire(result.result_code == kApiResultError, "stats accepted nonempty body");
        if (result.buffer != NULL)
            lineReuseBuffer(f.line, result.buffer);
    }
    context.max_response_body_size = 1;
    result                         = op->handler(f.node, estBytes(f.line, "{}", 2), &context);
    twfRequire(result.result_code == kApiResultError && result.buffer == NULL, "stats output allowance ignored");
    context.max_response_body_size   = 4096;
    context.working_memory_allowance = 4608;
    result                           = op->handler(f.node, estBytes(f.line, "{}", 2), &context);
    twfRequire(result.result_code == kApiResultError && result.buffer == NULL, "stats storage allowance ignored");
    context.working_memory_allowance = 16384;
    context.deadline_ms              = nodeApiNowMs();
    result                           = op->handler(f.node, estBytes(f.line, "{}", 2), &context);
    twfRequire(result.result_code == kApiResultError && result.buffer == NULL, "stats deadline ignored");
    closeFixture(&f);
}

typedef struct stats_publisher_s
{
    vmessserver_stats_t *stats;
    vmess_replay_t      *replay;
    pthread_barrier_t    barrier;
} stats_publisher_t;

enum
{
    kStatsSampleRounds         = 64,
    kStatsPublicationsPerRound = 32
};

static void statsBarrier(stats_publisher_t *publisher)
{
    int result = pthread_barrier_wait(&publisher->barrier);
    twfRequire(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD, "stats sampling barrier failed");
}

static void *publishConcurrentStats(void *context)
{
    stats_publisher_t *publisher = context;
    for (unsigned round = 0; round < kStatsSampleRounds; ++round)
    {
        statsBarrier(publisher);
        for (unsigned index = 0; index < kStatsPublicationsPerRound; ++index)
        {
            unsigned ordinal  = round * kStatsPublicationsPerRound + index;
            uint8_t  auth[16] = {(uint8_t) ordinal, (uint8_t) (ordinal >> 8)};
            uint8_t  key[16]  = {(uint8_t) ordinal, (uint8_t) (ordinal >> 8)};
            /* This unregistered thread touches published atomics and the
             * independently locked replay API, never a live line/map/pool. */
            atomic_fetch_add(&publisher->stats->tx_records, 1);
            atomic_fetch_add(&publisher->stats->rx_application_bytes, 2);
            discard vmessReplayAdmit(
                publisher->replay, auth, vector_uuid, key, vector_iv, 1700000000, 1700000000, 1000);
        }
        statsBarrier(publisher);
    }
    return NULL;
}

static cJSON *statsResponseJson(est_fixture_t *f, api_result_t result)
{
    twfRequire(result.buffer != NULL && sbufGetLength(result.buffer) < 4096, "stats sampling returned no bounded body");
    char   text[4096];
    size_t length = sbufGetLength(result.buffer);
    memoryCopy(text, sbufGetRawPtr(result.buffer), length);
    text[length] = '\0';
    twfRequire(strstr(text, "vmess-fixture") == NULL && strstr(text, "00010203-0405") == NULL,
               "stats leaked account credentials");
    cJSON *json = cJSON_Parse(text);
    twfRequire(json != NULL, "stats sampling returned malformed JSON");
    lineReuseBuffer(f->line, result.buffer);
    return json;
}

static void serverConcurrentStats(void)
{
    est_fixture_t f;
    setup(&f, 1000);
    twfRequire(vmessserverRegisterApi(f.node), "concurrent stats API registration failed");
    const node_api_operation_t *operation = nodeApiFind(f.node, "stats");
    twfRequire(operation != NULL, "concurrent stats registration missing");
    node_api_call_context_t context   = {.operation                = "stats",
                                         .deadline_ms              = nodeApiNowMs() + 10000,
                                         .max_response_body_size   = 4096,
                                         .working_memory_allowance = 16384};
    vmessserver_tstate_t   *ts        = tunnelGetState(f.node);
    stats_publisher_t       publisher = {.stats = &ts->stats, .replay = ts->replay};
    twfRequire(pthread_barrier_init(&publisher.barrier, NULL, 2) == 0, "stats publisher barrier initialization failed");
    pthread_t thread;
    twfRequire(pthread_create(&thread, NULL, publishConcurrentStats, &publisher) == 0,
               "stats publisher creation failed");
    uint64_t previous = 0;
    for (unsigned round = 0; round < kStatsSampleRounds; ++round)
    {
        statsBarrier(&publisher);
        api_result_t result = operation->handler(f.node, estBytes(f.line, "{}", 2), &context);
        cJSON       *json   = statsResponseJson(&f, result);
        if (result.result_code == kApiResultOk)
        {
            const cJSON *field = cJSON_GetObjectItemCaseSensitive(json, "tx_records");
            uint64_t     value = 0;
            twfRequire(cJSON_IsString(field) && jsonParseUint64String(field->valuestring, &value) &&
                           value >= previous && value <= (uint64_t) (round + 1) * kStatsPublicationsPerRound,
                       "concurrent stats published torn/backward/out-of-bound counter");
            previous = value;
        }
        else
        {
            const cJSON *error = cJSON_GetObjectItemCaseSensitive(json, "error");
            twfRequire(cJSON_IsString(error) && strcmp(error->valuestring, "busy") == 0,
                       "contended replay snapshot did not return bounded busy response");
        }
        cJSON_Delete(json);
        statsBarrier(&publisher);
    }
    twfRequire(pthread_join(thread, NULL) == 0 && pthread_barrier_destroy(&publisher.barrier) == 0,
               "stats publisher did not settle");
    api_result_t result = operation->handler(f.node, estBytes(f.line, "{}", 2), &context);
    twfRequire(result.result_code == kApiResultOk, "stats snapshot stayed busy after publisher joined");
    cJSON       *json    = statsResponseJson(&f, result);
    uint64_t     records = 0, bytes = 0;
    const cJSON *record_field = cJSON_GetObjectItemCaseSensitive(json, "tx_records");
    const cJSON *bytes_field  = cJSON_GetObjectItemCaseSensitive(json, "rx_application_bytes");
    twfRequire(cJSON_IsString(record_field) && cJSON_IsString(bytes_field) &&
                   jsonParseUint64String(record_field->valuestring, &records) &&
                   jsonParseUint64String(bytes_field->valuestring, &bytes) &&
                   records == kStatsSampleRounds * kStatsPublicationsPerRound && bytes == 2 * records,
               "final stats snapshot lost atomic publications");
    cJSON_Delete(json);
    char oversized[65];
    memset(oversized, ' ', sizeof(oversized));
    oversized[0] = '{';
    oversized[1] = '}';
    result       = operation->handler(f.node, estBytes(f.line, oversized, sizeof(oversized)), &context);
    twfRequire(result.result_code == kApiResultError, "stats accepted over-budget empty JSON input");
    if (result.buffer != NULL)
        lineReuseBuffer(f.line, result.buffer);
    nodeApiUnregister(f.node);
    twfRequire(nodeApiFind(f.node, "stats") == NULL, "stats descriptor survives unregister");
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
    TEST_RUN_CASE(packetaddrDeniedBeforeTable);
    TEST_RUN_CASE(packetaddrReplayBeforeTable);
    TEST_RUN_CASE(packetaddrParentDiesDuringDrain);
    TEST_RUN_CASE(serverConfiguration);
    TEST_RUN_CASE(serverStats);
    TEST_RUN_CASE(serverConcurrentStats);
    TEST_RUN_CASE(serverCounterWrap);
    TEST_RUN_CASE(deniedSecurityAndTermination);
    TEST_RUN_CASE(packetaddrBackends);
    TEST_RUN_CASE(packetaddrParentFinish);
    TEST_RUN_CASE(packetaddrFailedInit);
    TEST_RUN_CASE(packetaddrPermissionReentry);
    TEST_RUN_CASE(packetaddrDrainReentry);
    TEST_RUN_CASE(packetaddrQueuedReplyOwnership);
    TEST_RUN_CASE(serverStrictReceive);
    TEST_RUN_CASE(serverTerminationReentry);
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
