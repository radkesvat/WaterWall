/* CTest: waterwall.authentication_sync_unit
 * Actual client/server framing, mutation and ACKs with selected deliveries lost. */
#include "AuthenticationClient/structure.h"
#include "authentication_sync_peer.h"
#include "loggers/network_logger.h"
#include "test_assert.h"
#include "wevent.h"
#include <pthread.h>
#define require(c, m) TEST_REQUIRE(TEST_FAILURE_EXIT, c, m)

static atomic_ullong now_us;
unsigned long long   __wrap_getHRTimeUs(void);
unsigned long long   __wrap_getHRTimeUs(void)
{
    return atomicLoadU64(&now_us);
}
static worker_t                   workers[2];
static buffer_pool_t             *pools[2];
static wloop_t                   *loops[2];
static threadsafe_generic_pool_t *wios[2];
static master_pool_t             *ordinary[2][3], *line_master, *message_master, *wio_master;
static tunnel_chain_t            *chain;
static tunnel_t                  *clients[2], *transport, *server;
static unsigned                   drop_before, drop_ack, corrupt_ack, drop_auth, pushes, pulls;
static uint32_t                   last_correlation;
static uint64_t                   captured_sequence;
static char                      *captured_batch;
static sbuf_t                    *held_request, *saved_ack, *saved_session;
static bool                       hold_pull, hold_push, pause_before_session, pause_before_ack;
static unsigned                   last_response;
static int                        raw_response[2];
static char                       raw_body[2][128];
static unsigned                   refuse_create;
static bool                       refuse_add;
bool                              __real_usersCreate(users_t *users);
bool                              __wrap_usersCreate(users_t *users);
bool                              __wrap_usersCreate(users_t *users)
{
    if (refuse_create != 0 && --refuse_create == 0)
        return false; /* Expected table lock/resource initialization refusal. */
    return __real_usersCreate(users);
}
bool __real_usersAddUser(users_t *users, const user_t *user);
bool __wrap_usersAddUser(users_t *users, const user_t *user);
bool __wrap_usersAddUser(users_t *users, const user_t *user)
{
    if (refuse_add)
    {
        refuse_add = false;
        return false; /* Subset-copy refusal before any transport admission. */
    }
    return __real_usersAddUser(users, user);
}

static authenticationclient_tstate_t *state(unsigned i)
{
    return tunnelGetState(clients[i]);
}
static int owner(line_t *l)
{
    for (int i = 0; i < 2; ++i)
        if (clients[i] != NULL && state((unsigned) i)->control_line == l)
            return i;
    return -1;
}
static void disconnect(unsigned i)
{
    line_t *l = state(i)->control_line;
    if (l == NULL)
        return;
    lineRef(l);
    tunnelUpStreamFin(server, l);
    tunnelDownStreamFin(clients[i], l);
    require(! lineIsAlive(l), "disconnect left the client's owned line alive");
    lineUnref(l);
}
static void established(tunnel_t *t, line_t *l)
{
    discard t;
    int     i = owner(l);
    if (i >= 0)
        tunnelDownStreamEst(clients[i], l);
}
static void output(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard        t;
    const uint8_t *bytes = sbufGetRawPtr(b);
    const int      i     = owner(l);
    if (i < 0)
    {
        require(sbufGetLength(b) >= 29, "raw response was truncated");
        raw_response[lineGetWID(l)] = bytes[20];
        const uint32_t length       = min(sbufGetLength(b) - 29, (uint32_t) sizeof(raw_body[0]) - 1U);
        memoryCopy(raw_body[lineGetWID(l)], bytes + 29, length);
        raw_body[lineGetWID(l)][length] = 0;
        lineReuseBuffer(l, b);
        return;
    }
    if (sbufGetLength(b) >= 29)
        last_response = bytes[20];
    if (sbufGetLength(b) == 157 && bytes[20] == kAuthenticationClientResponseTypeSession && saved_session == NULL)
        saved_session = sbufDuplicate(b);
    if (sbufGetLength(b) >= 29 && bytes[20] == kAuthenticationClientResponseTypeSession && drop_auth > 0)
    {
        --drop_auth;
        lineReuseBuffer(l, b);
        disconnect((unsigned) i);
        return;
    }
    if (sbufGetLength(b) >= 29 && bytes[20] == kAuthenticationClientResponseTypeOk)
    {
        if (saved_ack != NULL)
            sbufDestroy(saved_ack);
        saved_ack = sbufDuplicate(b);
        if (drop_ack > 0)
        {
            --drop_ack;
            lineReuseBuffer(l, b);
            disconnect((unsigned) i);
            return;
        }
        if (corrupt_ack > 0)
        {
            --corrupt_ack;
            sbufGetMutablePtr(b)[29] = '!';
        }
    }
    if ((last_response == kAuthenticationClientResponseTypeSession && pause_before_session) ||
        (last_response == kAuthenticationClientResponseTypeOk && pause_before_ack))
    {
        pause_before_session = pause_before_ack = false;
        authenticationclientTunnelDownStreamPause(clients[i], l);
    }
    tunnelDownStreamPayload(clients[i], l, b);
}
static void input(tunnel_t *t, line_t *l, sbuf_t *b)
{
    const uint8_t *bytes = sbufGetRawPtr(b);
    require(sbufGetLength(b) >= 77, "client request was truncated");
    if (bytes[68] == kAuthenticationClientRequestTypePushUserStats)
    {
        ++pushes;
        uint32_t correlation;
        memoryCopy(&correlation, bytes + 69, 4);
        correlation           = ntohl(correlation);
        const uint32_t length = sbufGetLength(b) - 77;
        cJSON         *json   = cJSON_ParseWithLength((const char *) bytes + 77, length);
        uint64_t       sequence;
        require(getUint64FromJson(&sequence, cJSON_GetObjectItemCaseSensitive(json, "sequence")),
                "batch has no exact sequence");
        cJSON_Delete(json);
        if (captured_batch != NULL && sequence == captured_sequence)
        {
            require(stringLength(captured_batch) == length && memoryEqual(captured_batch, bytes + 77, length),
                    "retried batch bytes changed");
            require(correlation != last_correlation, "retry reused transport correlation");
        }
        else
        {
            memoryFree(captured_batch);
            captured_batch = memoryAllocate(length + 1U);
            memoryCopy(captured_batch, bytes + 77, length);
            captured_batch[length] = 0;
        }
        captured_sequence = sequence;
        last_correlation  = correlation;
        if (hold_push)
        {
            hold_push = false;
            require(held_request == NULL, "more than one held request");
            held_request = b;
            return;
        }
        if (drop_before > 0)
        {
            --drop_before;
            const int i = owner(l);
            lineReuseBuffer(l, b);
            require(i >= 0, "lost request has no owner");
            disconnect((unsigned) i);
            return;
        }
    }
    if (bytes[68] == kAuthenticationClientRequestTypeGetAllUsers)
    {
        ++pulls;
        if (hold_pull)
        {
            hold_pull = false;
            require(held_request == NULL, "more than one held pull");
            held_request = b;
            return;
        }
    }
    tunnelNextUpStreamPayload(t, l, b);
}
static void pump(unsigned milliseconds)
{
    atomicAddU64(&now_us, (uint64_t) milliseconds * 1000);
    for (unsigned j = 0; j < 4; ++j)
        discard wloopProcessEvents(loops[0], 0);
}
static void setup(unsigned users)
{
    atomicStoreU64(&now_us, 100000000);
    clients[0] = clients[1] = NULL;
    drop_before = drop_ack = corrupt_ack = drop_auth = pushes = pulls = 0;
    hold_pull = hold_push = pause_before_session = pause_before_ack = false;
    held_request = saved_ack = saved_session = NULL;
    captured_batch                           = NULL;
    captured_sequence                        = 0;
    GSTATE.flag_initialized                  = true;
    GSTATE.workers_count                     = 2;
    GSTATE.workers                           = workers;
    GSTATE.shortcut_buffer_pools             = pools;
    GSTATE.shortcut_loops                    = loops;
    GSTATE.shortcut_wios_pools               = wios;
    memoryZero(workers, sizeof(workers));
    message_master = masterpoolCreateWithCapacity(16);
    workerMessagesInstallMasterPoolCallbacks(message_master);
    GSTATE.masterpool_messages = message_master;
    wio_master                 = masterpoolCreateWithCapacity(16);
    for (wid_t i = 0; i < 2; ++i)
    {
        for (unsigned j = 0; j < 3; ++j)
            ordinary[i][j] = masterpoolCreateWithCapacity(8);
        pools[i] = bufferpoolCreate(
            ordinary[i][0], ordinary[i][1], ordinary[i][2], 4, 128 * 1024, 64 * 1024, 4096, 1048576, 1048576);
        require(pools[i] != NULL, "pool creation failed");
        wios[i]        = threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(wio_master, sizeof(wio_t), 8);
        workers[i].wid = i;
        workers[i].has_event_loop = true;
        workers[i].buffer_pool    = pools[i];
        workers[i].wios_pool      = wios[i];
        loops[i]                  = wloopCreate(WLOOP_FLAG_AUTO_FREE, pools[i], i);
        workers[i].loop           = loops[i];
        loops[i]->status          = WLOOP_STATUS_RUNNING;
        mutexInit(&workers[i].control_mutex);
        testWorkerBindWID(i);
        workerMessagesInit(&workers[i]);
        require(workerMessagesOpenAdmission(&workers[i]), "worker admission failed");
    }
    testWorkerBindWID(0);
    transport = tunnelCreate(NULL, 0, 0);
    require(transport != NULL, "transport creation failed");
    transport->fnPayloadU      = input;
    transport->fnPayloadD      = output;
    transport->fnEstD          = established;
    const uint32_t client_size = tunnelGetCorrectAlignedLineStateSize(sizeof(authenticationclient_lstate_t));
    server                     = authTestPeerCreate(client_size);
    authTestPeerPopulate(server, users);
    tunnelBind(transport, server);
    chain       = memoryCalloc(1, sizeof(*chain) + 2 * sizeof(generic_pool_t *));
    line_master = masterpoolCreateWithCapacity(16);
    for (unsigned i = 0; i < 2; ++i)
        chain->line_pools[i] = genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(
            line_master, sizeof(line_t) + client_size + authTestPeerLineSize(), 8);
}
static void start(unsigned i)
{
    tunnel_t *t = tunnelCreate(NULL, sizeof(authenticationclient_tstate_t), sizeof(authenticationclient_lstate_t));
    require(t != NULL, "client creation failed");
    clients[i]                        = t;
    t->chain                          = chain;
    t->next                           = transport;
    t->fnFinD                         = authenticationclientTunnelDownStreamFinish;
    t->fnEstD                         = authenticationclientTunnelDownStreamEst;
    t->fnPayloadD                     = authenticationclientTunnelDownStreamPayload;
    authenticationclient_tstate_t *ts = state(i);
    mutexInit(&ts->control_mutex);
    rwlockinit(&ts->users_lock);
    ts->users = memoryAllocateAligned(sizeof(users_t), 32);
    require(usersCreate(ts->users), "client users failed");
    ts->name                  = stringDuplicate(i == 0 ? "edge-a" : "edge-b");
    ts->secret                = stringDuplicate("secret");
    ts->started               = true;
    ts->users_generation      = 1;
    ts->next_correlation_id   = 1;
    ts->reconnect_interval_ms = 10;
    ts->request_timeout_ms    = 1000;
    ts->max_pending_requests  = 64;
    authenticationclientOpenControlLine(t);
}
static void teardown(void)
{
    testWorkerBindWID(0);
    if (held_request != NULL)
        sbufDestroy(held_request);
    if (saved_ack != NULL)
        sbufDestroy(saved_ack);
    if (saved_session != NULL)
        sbufDestroy(saved_session);
    memoryFree(captured_batch);
    for (unsigned i = 0; i < 2; ++i)
        if (clients[i] != NULL)
        {
            authenticationclientTunnelOnQuiesceRequest(clients[i], wwLifecycleProcessShutdown());
            authenticationclientTunnelOnWorkerQuiesce(clients[i], 0, wwLifecycleProcessShutdown());
            authenticationclientTunnelOnWorkerStop(clients[i], 0, wwLifecycleProcessShutdown());
        }
    workerMessagesCloseAdmission(&workers[0]);
    workerMessagesCleanupPending(&workers[0]);
    for (unsigned i = 0; i < 2; ++i)
        if (clients[i] != NULL)
            authenticationclientTunnelDestroy(clients[i], wwLifecycleProcessShutdown());
    authTestPeerDestroy(server);
    tunnelDestroy(transport);
    for (wid_t i = 0; i < 2; ++i)
    {
        testWorkerBindWID(i);
        workerMessagesDestroy(&workers[i]);
        wloopDestroy(&loops[i]);
        mutexDestroy(&workers[i].control_mutex);
        genericpoolDestroy(chain->line_pools[i]);
        threadsafegenericpoolDestroy(wios[i]);
        bufferpoolDestroy(pools[i]);
        for (unsigned j = 0; j < 3; ++j)
        {
            masterpoolMakeEmpty(ordinary[i][j]);
            masterpoolDestroy(ordinary[i][j]);
        }
    }
    masterpoolMakeEmpty(line_master);
    masterpoolMakeEmpty(message_master);
    masterpoolMakeEmpty(wio_master);
    masterpoolDestroy(line_master);
    masterpoolDestroy(message_master);
    masterpoolDestroy(wio_master);
    memoryFree(chain);
    testWorkerUnbindWID();
    GSTATE.flag_initialized    = false;
    GSTATE.workers             = NULL;
    GSTATE.masterpool_messages = NULL;
}
static void traffic(unsigned i, uint64_t bytes)
{
    user_handle_t handle;
    userHandleSet(&handle, state(i)->users_generation, 42);
    require(authenticationclientUserAddTraffic(clients[i], &handle, bytes, 0), "local traffic failed");
}
static uint64_t local(unsigned i, bool baseline)
{
    user_stat_t stats;
    user_t     *user = usersLookupByIdentifier(baseline ? state(i)->sync_baseline_users : state(i)->users, 42);
    userGetStats(user, &stats);
    return stats.traffic.u;
}
static void testLossAndOrdering(void)
{
    setup(1);
    drop_auth = 1;
    start(0);
    require(state(0)->accounting_epoch[0] == 0, "lost authentication reply enrolled the client");
    pump(10);
    require(authenticationclientIsReady(clients[0]), "fresh reenrollment failed");
    char enrolled_epoch[65];
    memoryCopy(enrolled_epoch, state(0)->accounting_epoch, sizeof(enrolled_epoch));
    tunnelDownStreamPayload(clients[0], state(0)->control_line, sbufDuplicate(saved_session));
    require(stringCompare(enrolled_epoch, state(0)->accounting_epoch) == 0,
            "stale initial reply replaced the established epoch");
    traffic(0, 10);
    drop_before = 1;
    authenticationclientRequestPush(clients[0]);
    require(state(0)->pending_batch != NULL && authTestPeerStats(server, 42).traffic.u == 0,
            "request loss changed accounting");
    traffic(0, 7);
    authenticationclientRequestPull(clients[0]);
    drop_ack = 2;
    pump(10);
    const uint64_t first_use = authTestPeerFirstUse(server);
    require(first_use != 0 && authTestPeerStats(server, 42).traffic.u == 10, "first batch did not apply");
    authTestPeerExpireSessions(server);
    pump(10);
    require(state(0)->pending_batch != NULL && authTestPeerStats(server, 42).traffic.u == 10,
            "repeated lost ACK charged twice");
    pump(10);
    require(state(0)->pending_batch == NULL && local(0, true) == 10 && local(0, false) == 17,
            "ACK/pull lost post-snapshot traffic");
    require(authTestPeerFirstUse(server) == first_use, "duplicate changed first-use timestamp");
    authenticationclientRequestPush(clients[0]);
    require(authTestPeerStats(server, 42).traffic.u == 17, "later traffic was lost or counted twice");
    authTestPeerPassword(server);
    traffic(0, 3);
    corrupt_ack = 1;
    authenticationclientRequestPush(clients[0]);
    require(state(0)->pending_batch != NULL && authTestPeerStats(server, 42).traffic.u == 20,
            "malformed ACK advanced baseline");
    pump(10);
    require(state(0)->pending_batch == NULL && authTestPeerStats(server, 42).traffic.u == 20,
            "durable-ID retry failed after password edit");

    hold_push = true;
    traffic(0, 2);
    authenticationclientRequestPush(clients[0]);
    require(held_request != NULL && state(0)->pending_batch != NULL, "push was not held");
    tunnelDownStreamPayload(clients[0], state(0)->control_line, sbufDuplicate(saved_ack));
    require(state(0)->pending_batch != NULL && local(0, true) == 20, "stale ACK settled the current batch");
    sbuf_t *pending = held_request;
    held_request    = NULL;
    tunnelUpStreamPayload(server, state(0)->control_line, pending);
    require(local(0, true) == 22, "held push failed to settle");

    hold_pull = true;
    authenticationclientRequestPull(clients[0]);
    require(held_request != NULL && state(0)->pull_in_flight, "pull was not held");
    traffic(0, 5);
    const unsigned before = pushes;
    authenticationclientRequestPush(clients[0]);
    require(pushes == before && state(0)->push_requested, "push overtook pull");
    sbuf_t *request = held_request;
    held_request    = NULL;
    tunnelUpStreamPayload(server, state(0)->control_line, request);
    require(authTestPeerStats(server, 42).traffic.u == 27 && local(0, true) == 27, "coalesced push disappeared");
    teardown();
}

static void deliverHeldRequest(void)
{
    require(held_request != NULL, "no request to deliver");
    sbuf_t *request = held_request;
    held_request    = NULL;
    tunnelUpStreamPayload(server, state(0)->control_line, request);
}

static void testRecurringPullDoesNotStarvePush(void)
{
    setup(1);
    start(0);
    authenticationclient_tstate_t *ts = state(0);
    ts->pull_interval_ms = ts->push_interval_ms = 1000;
    require(authenticationclientStartSyncTimer(clients[0]), "sync timer creation failed");
    hold_pull = true;
    authenticationclientRequestPull(clients[0]);
    uint64_t first_use = 0;
    for (unsigned i = 0; i < 4; ++i)
    {
        require(held_request != NULL && ts->pull_in_flight, "delayed pull was not outstanding");
        traffic(0, 10);
        ts->last_pull_sync_ms = ts->last_push_sync_ms = getTickMS() - 1000;
        authenticationclientSyncTimerCallback(ts->sync_timer);
        require(ts->pull_requested && ts->push_requested && pushes == i, "timer work was not coalesced");
        hold_pull = true;
        deliverHeldRequest();
        require(pushes == i + 1, "recurring pull starved a waiting usage push");
        const uint64_t expected = (uint64_t) (i + 1) * 10;
        require(authTestPeerStats(server, 42).traffic.u == expected && local(0, true) == expected &&
                    local(0, false) == expected && ts->pending_batch == NULL,
                "fair synchronization lost or duplicated traffic");
        if (i == 0)
            first_use = authTestPeerFirstUse(server);
        require(first_use != 0 && authTestPeerFirstUse(server) == first_use, "later batch changed first use");
    }
    deliverHeldRequest();
    require(pushes == 4 && ! ts->pull_in_flight && ! ts->push_in_flight, "synchronization did not settle");
    teardown();
}

static void testRequiredPullBeforeQueuedPush(void)
{
    setup(1);
    start(0);
    traffic(0, 10);
    disconnect(0);
    pause_before_session = true;
    pump(10);
    require(state(0)->authenticated && state(0)->write_paused && ! state(0)->pull_in_flight,
            "reconnect pull was not held by write pressure");
    authenticationclientRequestPush(clients[0]);
    hold_pull = true;
    authenticationclientTunnelDownStreamResume(clients[0], state(0)->control_line);
    require(pushes == 0 && state(0)->pull_in_flight, "queued push bypassed reconnect refresh");
    deliverHeldRequest();
    require(pushes == 1 && authTestPeerStats(server, 42).traffic.u == 10, "reconnect refresh lost queued usage");

    traffic(0, 5);
    pause_before_ack = true;
    authenticationclientRequestPush(clients[0]);
    require(state(0)->write_paused && ! state(0)->pull_in_flight && state(0)->pending_batch == NULL,
            "post-ACK pull was not held by write pressure");
    traffic(0, 7);
    authenticationclientRequestPush(clients[0]);
    hold_pull = true;
    authenticationclientTunnelDownStreamResume(clients[0], state(0)->control_line);
    require(pushes == 2 && state(0)->pull_in_flight, "queued push bypassed post-ACK refresh");
    deliverHeldRequest();
    require(pushes == 3 && authTestPeerStats(server, 42).traffic.u == 22 && local(0, true) == 22,
            "post-ACK refresh lost or duplicated queued usage");
    teardown();
}

static void testEmptyPushDoesNotDropPull(void)
{
    setup(1);
    start(0);
    hold_pull = true;
    authenticationclientRequestPull(clients[0]);
    authenticationclientRequestPull(clients[0]);
    authenticationclientRequestPush(clients[0]);
    require(state(0)->pull_requested && state(0)->push_requested, "sync requests were not queued");
    hold_pull = true;
    deliverHeldRequest();
    require(pushes == 0 && held_request != NULL && state(0)->pull_in_flight && ! state(0)->push_requested,
            "empty usage batch blocked an ordinary queued pull");
    deliverHeldRequest();
    require(! state(0)->pull_in_flight && ! state(0)->push_in_flight, "empty push work did not settle");
    teardown();
}

static void rawRequest(line_t *l, const uint8_t token[64], uint8_t type, const void *text, uint32_t length)
{
    sbuf_t        *message = bufferpoolGetBestFit(lineGetBufferPool(l), 77 + length, 0);
    sbufSetLength(message, 77 + length);
    uint8_t *bytes = sbufGetMutablePtr(message);
    memoryZero(bytes, 77);
    uint32_t number = htonl(73 + length);
    memoryCopy(bytes, &number, 4);
    memoryCopy(bytes + 4, token, 64);
    bytes[68] = type;
    number    = htonl(0xFFFF);
    memoryCopy(bytes + 69, &number, 4);
    number = htonl(length);
    memoryCopy(bytes + 73, &number, 4);
    memoryCopy(bytes + 77, text, length);
    tunnelUpStreamPayload(server, l, message);
}

static void rawBatch(line_t *l, const uint8_t token[64], const char *text)
{
    rawRequest(l, token, kAuthenticationClientRequestTypePushUserStats, text, (uint32_t) stringLength(text));
}

static void testStaleFullObjectRejected(void)
{
    setup(1);
    user_update_t initial = {.mask = kUserUpdateName | kUserUpdateStats, .name = "original", .stats.traffic.u = 100};
    authTestPeerSetUser(server, 42, &initial);
    authTestPeerPermissions(server, 0, true, true);
    start(0);
    cJSON *stale = authTestPeerUserJson(server, 42);
    require(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(stale, "name"), "renamed") != NULL,
            "stale user name setup failed");
    traffic(0, 10);
    authenticationclientRequestPush(clients[0]);
    require(authTestPeerStats(server, 42).traffic.u == 110, "usage fixture failed");
    uint8_t token[64];
    char    epoch[65];
    authTestPeerCredentials(server, 0, token, epoch);
    line_t *line = lineCreate(chain->line_pools, 0);
    tunnelUpStreamInit(server, line);
    char *before  = authTestPeerSnapshot(server);
    char *request = cJSON_PrintUnformatted(stale);
    rawRequest(line, token, kAuthenticationClientRequestTypeUpdateUser, request, (uint32_t) stringLength(request));
    char *after = authTestPeerSnapshot(server);
    require(raw_response[0] == 255 && stringCompare(before, after) == 0,
            "stale full-object edit changed usage or protected state");
    cJSON_free(before);
    cJSON_free(after);
    cJSON_free(request);
    cJSON_Delete(stale);
    tunnelUpStreamFin(server, line);
    lineDestroy(line);
    teardown();
}
static uint64_t jsonUnsigned(const cJSON *object, const char *key)
{
    uint64_t value;
    require(getUint64FromJson(&value, cJSON_GetObjectItemCaseSensitive(object, key)), "missing exact test value");
    return value;
}

static void expectPatchBytes(line_t *line, const uint8_t token[64], const void *request, uint32_t length, bool accepted)
{
    char *before    = authTestPeerSnapshot(server);
    raw_response[0] = -1;
    rawRequest(line, token, kAuthenticationClientRequestTypeUpdateUser, request, length);
    char *after = authTestPeerSnapshot(server);
    require(raw_response[0] == (accepted ? 0 : 255), "patch returned the wrong protocol result");
    if (! accepted)
        require(stringCompare(before, after) == 0, "rejected patch changed users, indexes, revisions or checkpoints");
    else
    {
        require(stringCompare(raw_body[0], "user-updated") == 0, "patch success response changed");
        cJSON *old = cJSON_Parse(before), *current = cJSON_Parse(after);
        require(jsonUnsigned(current, "config-revision") == jsonUnsigned(old, "config-revision") + 1 &&
                    jsonUnsigned(current, "stats-revision") == jsonUnsigned(old, "stats-revision") &&
                    cJSON_Compare(cJSON_GetObjectItemCaseSensitive(current, "checkpoints"),
                                  cJSON_GetObjectItemCaseSensitive(old, "checkpoints"),
                                  true),
                "patch changed accounting or did not increment configuration exactly once");
        cJSON_Delete(old);
        cJSON_Delete(current);
    }
    cJSON_free(before);
    cJSON_free(after);
}

static void expectPatch(line_t *line, const uint8_t token[64], const char *request, bool accepted)
{
    expectPatchBytes(line, token, request, (uint32_t) stringLength(request), accepted);
}

static void testConfigPatches(void)
{
    setup(2);
    user_update_t initial = {
        .mask = kUserUpdateName | kUserUpdateEmail | kUserUpdateNotes | kUserUpdateTimeInfo | kUserUpdateStats |
                kUserUpdateLimit | kUserUpdateRecordStatInterval,
        .name     = "original",
        .email    = "old@example.test",
        .notes    = "keep",
        .timeinfo = {123, 456, UINT64_MAX, UINT64_MAX},
        .stats    = {.ips = 7, .devices = 8, .cons_in = 9, .cons_out = 10, .speed = {11, 12}, .traffic = {100, 200}},
        .limit    = {.traffic   = {1001, 1002, 1003},
                     .bandwidth = {1004, 1005},
                     .ips       = 1006,
                     .devices   = 1007,
                     .cons_in   = 1008,
                     .cons_out  = 1009},
        .record_stat_interval_ms = 1234};
    authTestPeerSetUser(server, 42, &initial);
    user_update_t other = {.mask                  = kUserUpdateName | kUserUpdateWireGuardAllowedIps,
                           .name                  = "taken",
                           .wireguard_allowed_ips = "192.0.2.0/24"};
    authTestPeerSetUser(server, 43, &other);
    authTestPeerInsertUser(server, INT64_MAX, "high-signed");
    authTestPeerInsertUser(server, UINT64_MAX, "high-unsigned");
    authTestPeerPermissions(server, 0, true, true);
    start(0);
    uint8_t token[64];
    char    epoch[65];
    authTestPeerCredentials(server, 0, token, epoch);
    line_t *line = lineCreate(chain->line_pools, 0);
    tunnelUpStreamInit(server, line);

    expectPatch(line, token, " \r\n{\"id\":42,\"name\":\"Alice\"}\t ", true);
    expectPatch(line, token, "{\"id\":42,\"email\":\"new@example.test\"}", true);
    expectPatch(line, token, "{\"id\":42,\"name\":\"Alice\"}", true); /* same-value assignments still revise */
    expectPatch(line,
                token,
                "{\"id\":42,\"limit\":{\"traffic\":{\"total\":5000}},"
                "\"time\":{\"expire-after-first-usage-ms\":9000}}",
                true);
    cJSON *json          = authTestPeerUserJson(server, 42);
    cJSON *limit         = cJSON_GetObjectItemCaseSensitive(json, "limit");
    cJSON *traffic_limit = cJSON_GetObjectItemCaseSensitive(limit, "traffic");
    cJSON *bandwidth     = cJSON_GetObjectItemCaseSensitive(limit, "bandwidth");
    cJSON *time          = cJSON_GetObjectItemCaseSensitive(json, "time");
    require(jsonUnsigned(traffic_limit, "up") == 1001 && jsonUnsigned(traffic_limit, "down") == 1002 &&
                jsonUnsigned(traffic_limit, "total") == 5000 && jsonUnsigned(bandwidth, "up") == 1004 &&
                jsonUnsigned(bandwidth, "down") == 1005 && jsonUnsigned(limit, "ips") == 1006 &&
                jsonUnsigned(limit, "devices") == 1007 && jsonUnsigned(limit, "connections-in") == 1008 &&
                jsonUnsigned(limit, "connections-out") == 1009 && jsonUnsigned(time, "created-at-ms") == 123 &&
                jsonUnsigned(time, "first-usage-at-ms") == 456 && jsonUnsigned(time, "expire-at-ms") == UINT64_MAX &&
                jsonUnsigned(time, "expire-after-first-usage-ms") == 9000 &&
                jsonUnsigned(json, "record-stat-interval-ms") == 1234 &&
                stringCompare(cJSON_GetObjectItemCaseSensitive(json, "email")->valuestring, "new@example.test") == 0,
            "independent or nested patches reset omitted leaves or timestamps");
    cJSON_Delete(json);
    user_stat_t stats = authTestPeerStats(server, 42);
    require(stats.traffic.u == 100 && stats.traffic.d == 200 && stats.ips == 7 && stats.devices == 8 &&
                stats.cons_in == 9 && stats.cons_out == 10 && stats.speed.u == 11 && stats.speed.d == 12,
            "configuration patch overwrote stored statistics");

    const char *invalid[] = {"{}",
                             "{\"id\":42}",
                             "{\"name\":\"x\"}",
                             "{\"id\":0,\"name\":\"x\"}",
                             "{\"id\":42,\"name\":\"x\",\"stats\":{\"traffic\":{\"up\":0}}}",
                             "{\"id\":42,\"name\":\"x\",\"password\":\"account-0\"}",
                             "{\"id\":42,\"name\":\"x\",\"uuid\":\"x\"}",
                             "{\"id\":42,\"name\":\"x\",\"wireguard-publickey\":\"x\"}",
                             "{\"id\":42,\"name\":\"x\",\"runtime\":{}}",
                             "{\"id\":42,\"name\":\"x\",\"client-view-expires-at-ms\":0}",
                             "{\"id\":42,\"name\":\"x\",\"created-at-ms\":0}",
                             "{\"id\":42,\"name\":\"x\",\"time\":{\"created-at-ms\":0}}",
                             "{\"id\":42,\"name\":\"x\",\"time\":{\"first-usage-at-ms\":0}}",
                             "{\"id\":42,\"name\":\"x\",\"user-id\":42}",
                             "{\"id\":42,\"Name\":\"x\"}",
                             "{\"id\":42,\"limit.traffic.total\":0}",
                             "{\"id\":42,\"limit\":{\"traffic\":{\"up\":1,\"other\":0}}}",
                             "{\"id\":42,\"name\":\"x\",\"time\":{}}",
                             "{\"id\":42,\"name\":\"x\",\"limit\":{}}",
                             "{\"id\":42,\"name\":\"x\",\"limit\":{\"traffic\":{}}}",
                             "{\"id\":42,\"limit\":{\"bandwidth\":{}}}",
                             "{\"id\":42,\"name\":null}",
                             "{\"id\":42,\"time\":null}",
                             "{\"id\":42,\"enabled\":1}",
                             "{\"id\":42,\"email\":false}",
                             "{\"id\":42,\"name\":\"x\",\"name\":\"y\"}",
                             "{\"id\":42,\"name\":\"x\",\"na\\u006de\":\"y\"}",
                             "{\"id\":42,\"limit\":{\"ips\":1,\"ips\":2}}",
                             "{\"id\":42,\"limit\":{\"traffic\":{\"up\":1,\"up\":2}}}",
                             "{\"id\":42,\"time\":{\"expire-at-ms\":1,\"expire-at-ms\":2}}",
                             "{\"id\":42,\"notes\":\"\\u0000\"}",
                             "{\"id\":42,\"notes\":\"\xc0\xaf\"}",
                             "{\"id\":42,\"notes\":\"x\"} trailing",
                             "{\"id\":42,\"notes\":\"x\"}{}",
                             "{\"id\":42.0,\"name\":\"x\"}",
                             "{\"id\":42e0,\"name\":\"x\"}",
                             "{\"id\":-42,\"name\":\"x\"}",
                             "{\"id\":18446744073709551616,\"name\":\"x\"}",
                             "{\"id\":42,\"gid\":-1}",
                             "{\"id\":42,\"gid\":1.5}",
                             "{\"id\":42,\"gid\":1e3}",
                             "{\"id\":42,\"gid\":\"18446744073709551616\"}",
                             "{\"id\":42,\"limit\":{\"ips\":9223372036854775808.0}}",
                             "{\"id\":42,\"record-stat-interval-ms\":2147483648}",
                             "{\"id\":42,\"name\":\"taken\",\"email\":\"bad\"}",
                             "{\"id\":42,\"name\":\"bad\",\"wireguard-allowed-ips\":\"192.0.2.8/32\"}",
                             "{\"id\":42,\"name\":\"bad\",\"wireguard-allowed-ips\":\"invalid\"}"};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        expectPatch(line, token, invalid[i], false);
    static const char raw_nul[] = "{\"id\":42,\"notes\":\"x\"}\0ignored";
    expectPatchBytes(line, token, raw_nul, sizeof(raw_nul) - 1, false);
    expectPatch(line, token, "{\"id\":999,\"name\":\"missing\"}", false);
    require(stringCompare(raw_body[0], "user-not-found") == 0, "unknown ID was not reported");
    expectPatch(line, token, "{\"id\":9223372036854775807,\"gid\":9223372036854775807}", true);
    expectPatch(line, token, "{\"id\":\"18446744073709551615\",\"gid\":\"18446744073709551615\"}", true);
    json = authTestPeerUserJson(server, UINT64_MAX);
    require(jsonUnsigned(json, "gid") == UINT64_MAX, "high integer was rounded");
    cJSON_Delete(json);
    expectPatch(line,
                token,
                "{\"id\":42,\"record-stat-interval-ms\":2147483647,\"gid\":99,\"enabled\":false,"
                "\"wireguard-allowed-ips\":\"198.51.100.0/24\",\"limit\":{\"traffic\":{\"up\":11,\"down\":12},"
                "\"bandwidth\":{\"up\":13,\"down\":14},\"ips\":15,\"devices\":16,"
                "\"connections-in\":17,\"connections-out\":18}}",
                true);
    json          = authTestPeerUserJson(server, 42);
    limit         = cJSON_GetObjectItemCaseSensitive(json, "limit");
    traffic_limit = cJSON_GetObjectItemCaseSensitive(limit, "traffic");
    bandwidth     = cJSON_GetObjectItemCaseSensitive(limit, "bandwidth");
    require(jsonUnsigned(json, "gid") == 99 && jsonUnsigned(json, "record-stat-interval-ms") == INT_MAX &&
                jsonUnsigned(traffic_limit, "up") == 11 && jsonUnsigned(traffic_limit, "down") == 12 &&
                jsonUnsigned(traffic_limit, "total") == 5000 && jsonUnsigned(bandwidth, "up") == 13 &&
                jsonUnsigned(bandwidth, "down") == 14 && jsonUnsigned(limit, "ips") == 15 &&
                jsonUnsigned(limit, "devices") == 16 && jsonUnsigned(limit, "connections-in") == 17 &&
                jsonUnsigned(limit, "connections-out") == 18 &&
                stringCompare(cJSON_GetObjectItemCaseSensitive(json, "wireguard-allowed-ips")->valuestring,
                              "198.51.100.0/24") == 0,
            "accepted configuration leaves were not applied");
    cJSON_Delete(json);
    expectPatch(line,
                token,
                "{\"id\":42,\"name\":\"\",\"email\":\"\",\"notes\":\"\",\"wireguard-allowed-ips\":\"\","
                "\"record-stat-interval-ms\":0,\"limit\":{\"traffic\":{\"up\":0,\"down\":0,\"total\":0},"
                "\"bandwidth\":{\"up\":0,\"down\":0},\"ips\":0,\"devices\":0,\"connections-in\":0,"
                "\"connections-out\":0},\"time\":{\"expire-at-ms\":0,\"expire-after-first-usage-ms\":0}}",
                true);
    json = authTestPeerUserJson(server, 42);
    time = cJSON_GetObjectItemCaseSensitive(json, "time");
    require(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(json, "enabled")) &&
                jsonUnsigned(time, "first-usage-at-ms") == 456 && jsonUnsigned(time, "created-at-ms") == 123 &&
                ! cJSON_HasObjectItem(time, "expire-at-ms") &&
                ! cJSON_HasObjectItem(time, "expire-after-first-usage-ms") &&
                jsonUnsigned(json, "record-stat-interval-ms") == 0 && ! cJSON_HasObjectItem(json, "limit") &&
                ! cJSON_HasObjectItem(json, "name") && ! cJSON_HasObjectItem(json, "email") &&
                ! cJSON_HasObjectItem(json, "notes") && ! cJSON_HasObjectItem(json, "wireguard-allowed-ips"),
            "explicit clears changed omitted state or did not clear selected leaves");
    cJSON_Delete(json);
    authTestPeerPermissions(server, 0, false, true);
    expectPatch(line, token, "{\"id\":42,\"name\":\"denied\"}", false);
    require(stringCompare(raw_body[0], "user-write-not-allowed") == 0, "stats permission permitted configuration edit");
    tunnelUpStreamFin(server, line);
    lineDestroy(line);
    teardown();
}

static void testEditDuringAccounting(void)
{
    setup(1);
    user_update_t initial = {.mask                   = kUserUpdateName | kUserUpdateStats | kUserUpdateTimeInfo,
                             .name                   = "original",
                             .stats.traffic.u        = 100,
                             .timeinfo.created_at_ms = 123};
    authTestPeerSetUser(server, 42, &initial);
    authTestPeerPermissions(server, 0, true, true);
    start(0);
    uint8_t token[64];
    char    epoch[65];
    authTestPeerCredentials(server, 0, token, epoch);
    line_t *line = lineCreate(chain->line_pools, 0);
    tunnelUpStreamInit(server, line);
    user_ip_key_t ip = {.type = 4, .bytes = {192, 0, 2, 1}};
    require(usersTryAdmitConnectionByIdentifier(state(0)->users, 42, &ip, getTimeOfDayMS()) == kUserAdmissionOk,
            "client reservation setup failed");
    const uint64_t old_projection = getTimeOfDayMS() + 100000;
    userSetClientViewExpiry(usersLookupByIdentifier(state(0)->users, 42), old_projection, true);
    expectPatch(
        line, token, "{\"id\":42,\"name\":\"before\",\"time\":{\"expire-at-ms\":\"18446744073709551615\"}}", true);
    require(authTestPeerFirstUse(server) == 0, "patch created first use");
    authenticationclientRequestPull(clients[0]);
    user_t *user = usersLookupByIdentifier(state(0)->users, 42);
    require(user->runtime.active_cons_out == 1 && user->runtime.ip_usage_count == 1 && user->client_view_expiry_valid &&
                user->client_view_expires_at_ms != old_projection,
            "configuration refresh lost runtime state or reused stale expiry projection");
    traffic(0, 10);
    drop_ack = 1;
    authenticationclientRequestPush(clients[0]);
    const uint64_t first_use = authTestPeerFirstUse(server);
    require(first_use != 0 && state(0)->pending_batch != NULL && authTestPeerStats(server, 42).traffic.u == 110,
            "lost-ACK edit fixture failed");
    expectPatch(line, token, "{\"id\":42,\"name\":\"after\"}", true);
    require(authTestPeerStats(server, 42).traffic.u == 110 && authTestPeerFirstUse(server) == first_use,
            "name patch overwrote newer usage or first use");
    traffic(0, 7);
    pump(10);
    require(state(0)->pending_batch == NULL && local(0, true) == 110 && local(0, false) == 117 &&
                authTestPeerStats(server, 42).traffic.u == 110 && authTestPeerFirstUse(server) == first_use,
            "edit during lost ACK changed replay identity or lost newer traffic");
    authenticationclientRequestPush(clients[0]);
    require(authTestPeerStats(server, 42).traffic.u == 117, "post-edit local traffic was not reportable");
    user = usersLookupByIdentifier(state(0)->users, 42);
    require(user->runtime.active_cons_out == 1 && user->timeinfo.created_at_ms == 123 &&
                stringCompare(user->name, "after") == 0,
            "patch refresh lost identity, creation metadata or active state");
    usersReleaseConnectionByIdentifier(state(0)->users, 42, &ip);
    require(user->runtime.active_cons_out == 0, "post-refresh reservation did not release");
    tunnelUpStreamFin(server, line);
    lineDestroy(line);
    teardown();
}

static void testStrictTrafficBatches(void)
{
    setup(2);
    authTestPeerPermissions(server, 0, true, true);
    start(0);
    uint8_t token[64];
    char    epoch[65], text[1024];
    authTestPeerCredentials(server, 0, token, epoch);
    line_t *line = lineCreate(chain->line_pools, 0);
    tunnelUpStreamInit(server, line);
    const char *formats[] = {
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0}],\"speed\":5}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"ips\":1}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0},"
        "{\"id\":43,\"up\":1,\"down\":0,\"connections-out\":1}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":1}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"traffic\":{\"up\":100}}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"seq\\u0075ence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"\\u0069d\":42,\"up\":1,\"down\":0}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0}]} trailing",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1.0,\"down\":0}]}",
        "{\"epoch\":\"%s\",\"sequence\":1e0,\"users\":[{\"id\":42,\"up\":1,\"down\":0}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0},"
        "{\"id\":43,\"up\":0,\"down\":0}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0}],\"other\":\"\\u0000\"}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0}],\"other\":\"\xed\xa0\x80\"}"};
    for (unsigned i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i)
    {
        snprintf(text, sizeof(text), formats[i], epoch);
        char *before = authTestPeerSnapshot(server);
        rawBatch(line, token, text);
        char *after = authTestPeerSnapshot(server);
        require(raw_response[0] == 255 && stringCompare(before, after) == 0,
                "invalid/nontraffic batch mutated users, revisions or checkpoint");
        cJSON_free(before);
        cJSON_free(after);
    }
    snprintf(
        text, sizeof(text), "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":3,\"down\":0}]}", epoch);
    rawBatch(line, token, text);
    require(raw_response[0] == 0 && authTestPeerStats(server, 42).traffic.u == 3 &&
                authTestPeerSequence(server, 0) == 1,
            "rejected schema consumed expected sequence");
    char *before = authTestPeerSnapshot(server);
    rawBatch(line, token, text);
    char *after = authTestPeerSnapshot(server);
    require(raw_response[0] == 0 && stringCompare(before, after) == 0, "exact replay changed accepted batch state");
    cJSON_free(before);
    cJSON_free(after);
    before              = authTestPeerSnapshot(server);
    const char *removed = "{\"id\":42,\"password\":\"account-0\",\"stats\":{\"traffic\":{\"up\":99,\"down\":0}}}";
    rawRequest(line, token, 8, removed, (uint32_t) stringLength(removed));
    after = authTestPeerSnapshot(server);
    require(raw_response[0] == 255 && stringCompare(raw_body[0], "unknown-request-type") == 0 &&
                stringCompare(before, after) == 0,
            "removed raw traffic opcode remained active");
    cJSON_free(before);
    cJSON_free(after);
    snprintf(text,
             sizeof(text),
             "{\"epoch\":\"%s\",\"sequence\":2,\"users\":[{\"id\":42,\"up\":\"18446744073709551615\",\"down\":0}]}",
             epoch);
    authTestPeerPermissions(server, 0, true, false);
    before = authTestPeerSnapshot(server);
    rawBatch(line, token, text);
    after = authTestPeerSnapshot(server);
    require(raw_response[0] == 255 && stringCompare(raw_body[0], "stats-push-not-allowed") == 0 &&
                stringCompare(before, after) == 0,
            "user-write permission permitted stats push");
    cJSON_free(before);
    cJSON_free(after);
    expectPatch(line, token, "{\"id\":42,\"notes\":\"write only\"}", true);
    authTestPeerPermissions(server, 0, true, true);
    const uint64_t first_use = authTestPeerFirstUse(server);
    rawBatch(line, token, text);
    require(raw_response[0] == 0 && authTestPeerStats(server, 42).traffic.u == UINT64_MAX &&
                authTestPeerFirstUse(server) == first_use,
            "traffic saturation or first-use preservation failed");
    tunnelUpStreamFin(server, line);
    lineDestroy(line);
    teardown();
}

static void testRejectionsAndContinuity(void)
{
    setup(1);
    start(0);
    traffic(0, 10);
    authenticationclientRequestPush(clients[0]);
    uint8_t token[64];
    char    epoch[65], text[1024];
    authTestPeerCredentials(server, 0, token, epoch);
    const char *entries[] = {"{\"id\":42,\"up\":20,\"down\":0}",
                             "{\"id\":42,\"up\":5,\"down\":0},{\"id\":999,\"up\":1,\"down\":0}",
                             "{\"id\":42,\"up\":5,\"down\":0},{\"id\":42,\"up\":1,\"down\":0}"};
    for (unsigned i = 0; i < 3; ++i)
    {
        snprintf(
            text, sizeof(text), "{\"epoch\":\"%s\",\"sequence\":%u,\"users\":[%s]}", epoch, i == 0 ? 1 : 2, entries[i]);
        rawBatch(state(0)->control_line, token, text);
        require(last_response == 255 && authTestPeerStats(server, 42).traffic.u == 10 &&
                    authTestPeerSequence(server, 0) == 1,
                "invalid later entry or replay partially mutated the store");
    }
    snprintf(text, sizeof(text), "{\"epoch\":\"%s\",\"sequence\":3,\"users\":[%s]}", epoch, entries[0]);
    rawBatch(state(0)->control_line, token, text);
    require(authTestPeerSequence(server, 0) == 1, "sequence gap mutated checkpoint");
    text[10] = text[10] == 'a' ? 'b' : 'a';
    rawBatch(state(0)->control_line, token, text);
    require(last_response == 255 && authTestPeerStats(server, 42).traffic.u == 10, "stale epoch mutated accounting");
    authTestPeerRemoveUser(server);
    rawBatch(state(0)->control_line, token, captured_batch); /* exact replay before current-account validation */
    require(last_response == 0 && authTestPeerSequence(server, 0) == 1,
            "exact replay after removal was not acknowledged");
    teardown();

    setup(1);
    start(0);
    traffic(0, 9);
    drop_ack = 1;
    authenticationclientRequestPush(clients[0]);
    authTestPeerLoseEpoch(server, 0);
    pump(10);
    require(authenticationclientGetState(clients[0]) == kAuthenticationClientStateContinuityError &&
                state(0)->pending_batch != NULL && state(0)->control_line == NULL,
            "lost continuity silently replayed or discarded an uncertain batch");
    const unsigned attempts = pushes;
    pump(100000);
    require(pushes == attempts && state(0)->reconnect_timer == NULL, "continuity error spun automatic synchronization");
    teardown();

    setup(1);
    start(0);
    disconnect(0);
    authTestPeerLoseEpoch(server, 0);
    pump(10);
    pump(10);
    require(authenticationclientIsReady(clients[0]), "safe fresh enrollment without uncertain batch failed");
    teardown();
}

typedef struct concurrent_s
{
    unsigned wid;
    line_t  *line;
    uint8_t  token[64];
    char     epoch[65];
    uint64_t first;
} concurrent_t;
static void *concurrentBatches(void *argument)
{
    concurrent_t *context = argument;
    testWorkerBindWID((wid_t) context->wid);
    for (unsigned i = 0; i < 100; ++i)
    {
        char text[256];
        snprintf(text,
                 sizeof(text),
                 "{\"epoch\":\"%s\",\"sequence\":%" PRIu64 ",\"users\":[{\"id\":42,\"up\":1,\"down\":0}]}",
                 context->epoch,
                 context->first + i);
        raw_response[context->wid] = -1;
        rawBatch(context->line, context->token, text);
        require(raw_response[context->wid] == 0, "concurrent real batch failed");
    }
    tunnelUpStreamFin(server, context->line);
    lineDestroy(context->line);
    testWorkerUnbindWID();
    return NULL;
}
static void testConcurrentAndSubsets(void)
{
    setup(1);
    start(0);
    start(1);
    concurrent_t contexts[2];
    pthread_t    threads[2];
    for (unsigned i = 0; i < 2; ++i)
    {
        testWorkerBindWID((wid_t) i);
        contexts[i] = (concurrent_t) {.wid = i, .first = 1};
        authTestPeerCredentials(server, i, contexts[i].token, contexts[i].epoch);
        contexts[i].line = lineCreate(chain->line_pools, (wid_t) i);
        tunnelUpStreamInit(server, contexts[i].line);
        bufferpoolResetThreadOwnership(pools[i]);
#if POOL_THREAD_CHECK
        chain->line_pools[i]->tid = 0; /* exclusive ownership transfer to/from joined worker */
#endif
    }
    for (unsigned i = 0; i < 2; ++i)
        require(pthread_create(&threads[i], NULL, concurrentBatches, &contexts[i]) == 0,
                "concurrent batch thread failed");
    for (unsigned i = 0; i < 2; ++i)
        pthread_join(threads[i], NULL);
    for (unsigned i = 0; i < 2; ++i)
    {
        bufferpoolResetThreadOwnership(pools[i]);
#if POOL_THREAD_CHECK
        chain->line_pools[i]->tid = 0; /* exclusive ownership transfer to/from joined worker */
#endif
    }
    testWorkerBindWID(0);
    require(authTestPeerStats(server, 42).traffic.u == 200 && authTestPeerSequence(server, 0) == 100 &&
                authTestPeerSequence(server, 1) == 100,
            "concurrent contributions or bounded checkpoint sequence failed");
    teardown();

    setup(4097);
    start(0);
    require(authenticationclientIsReady(clients[0]), "large table pull failed");
    for (size_t i = 0; i < usersCount(state(0)->users); ++i)
        userAddTraffic(usersGetAt(state(0)->users, i), 1, 0);
    authenticationclientRequestPush(clients[0]);
    require(authTestPeerSequence(server, 0) == 2 && state(0)->pending_batch == NULL,
            "bounded subset work did not complete");
    for (uint64_t id = 42; id < 42 + 4097; ++id)
        require(authTestPeerStats(server, id).traffic.u == 1, "subset ACK advanced unsent users or lost their usage");
    teardown();
}
static void testBatchConstructionRefusal(void)
{
    for (unsigned kind = 0; kind < 2; ++kind)
    {
        setup(1);
        start(0);
        traffic(0, 1);
        if (kind == 0)
            refuse_create = 3;
        else
            refuse_add = true;
        authenticationclientRequestPush(clients[0]);
        require(state(0)->pending_batch == NULL && local(0, true) == 0 && local(0, false) == 1,
                "construction refusal lost traffic or advanced baseline");
        require(refuse_create == 0 && ! refuse_add, "construction refusal was not reached");
        authenticationclientRequestPush(clients[0]);
        require(authTestPeerStats(server, 42).traffic.u == 1, "refusal prevented a later valid batch");
        teardown();
    }
}
int main(void)
{
    testCaseSet("authentication sync loss and continuity");
    require(createNetworkLogger(NULL, false) != NULL, "logger failed");
    require(globalstateInitializeSecureRandom() && wCryptoGlobalInit() == kWCryptoOk, "crypto failed");
    testStaleFullObjectRejected();
    testConfigPatches();
    testEditDuringAccounting();
    testStrictTrafficBatches();
    testLossAndOrdering();
    testRecurringPullDoesNotStarvePush();
    testRequiredPullBeforeQueuedPush();
    testEmptyPushDoesNotDropPull();
    testRejectionsAndContinuity();
    testConcurrentAndSubsets();
    testBatchConstructionRefusal();
    wCryptoGlobalCleanup();
    globalstateDestroySecureRandom();
    networkloggerDestroy();
    return 0;
}
