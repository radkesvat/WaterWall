/* CTest: waterwall.authentication_sync_unit
 * Actual client/server framing, mutation and ACKs with selected deliveries lost. */
#include "AuthenticationClient/structure.h"
#include "api/node_api.h"
#include "authentication_sync_peer.h"
#include "fixtures/user_runtime.h"
#include "loggers/network_logger.h"
#include "test_assert.h"
#include "wevent.h"
#include <math.h>
#include <pthread.h>
#define require(c, m) TEST_REQUIRE(TEST_FAILURE_EXIT, c, m)

uint32_t __wrap_fastRand32(void);
uint32_t __wrap_fastRand32(void)
{
    return 0; /* Deterministic lower jitter bound in fake-clock fixtures. */
}

static atomic_ullong     now_us;
static atomic_ullong     server_wall_ms, client_wall_ms;
static thread_local bool in_server;
static unsigned          fail_server_rng_call, server_rng_calls;
bool                     __real_secureRandomBytes(void *bytes, size_t size);
bool                     __wrap_secureRandomBytes(void *bytes, size_t size);
bool                     __wrap_secureRandomBytes(void *bytes, size_t size)
{
    if (in_server && fail_server_rng_call != 0 && ++server_rng_calls == fail_server_rng_call)
    {
        fail_server_rng_call = 0;
        return false;
    }
    return __real_secureRandomBytes(bytes, size);
}
int                      __wrap_gettimeofday(struct timeval *tv, void *tz);
int                      __wrap_gettimeofday(struct timeval *tv, void *tz)
{
    discard        tz;
    const uint64_t ms = atomicLoadU64(in_server ? &server_wall_ms : &client_wall_ms);
    tv->tv_sec        = (time_t) (ms / 1000);
    tv->tv_usec       = (suseconds_t) ((ms % 1000) * 1000);
    return 0;
}
unsigned long long __wrap_getHRTimeUs(void);
unsigned long long __wrap_getHRTimeUs(void)
{
    const uint64_t now = atomicLoadU64(&now_us);
    /* Deliberately different origins AND rates: server runs at 2x client. */
    return in_server ? 900000000ULL + (now >= 100000000ULL ? 2 * (now - 100000000ULL) : 0) : now;
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
static int                        captured_owner;
static unsigned                   clock_fault;
static unsigned                   ack_fault;
static unsigned                   missing_proof_fault;
static char                      *captured_batch;
static sbuf_t                    *held_request, *saved_ack, *saved_session;
static bool                       hold_pull, hold_push, pause_before_session, pause_before_ack;
static unsigned                   last_response;
static unsigned                   page_requests;
static uint64_t                   hold_page_position;
static bool                       hold_final_page;
static int                        raw_response[2];
static char                       raw_body[2][128];
static bool                       refuse_snapshot;
static void                       requireSyncPhase(const char *expected);
static sbuf_t                    *authPageResponseFault(sbuf_t *buffer);
bool __real_usersSnapshotAccounting(const users_t *, user_accounting_snapshot_t **, size_t *);
bool __wrap_usersSnapshotAccounting(const users_t *users, user_accounting_snapshot_t **entries, size_t *count);
bool __wrap_usersSnapshotAccounting(const users_t *users, user_accounting_snapshot_t **entries, size_t *count)
{
    if (refuse_snapshot)
    {
        refuse_snapshot = false;
        *entries        = NULL;
        *count          = 0;
        return false; /* Expected snapshot geometry refusal, before publication. */
    }
    return __real_usersSnapshotAccounting(users, entries, count);
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
static sbuf_t *faultClockMetadata(sbuf_t *b)
{
    if (clock_fault == 0 || sbufGetLength(b) < 29 ||
        ((const uint8_t *) sbufGetRawPtr(b))[20] != kAuthenticationClientResponseTypeUsers)
        return b;
    cJSON *json = cJSON_ParseWithLength((const char *) sbufGetRawPtr(b) + 29, sbufGetLength(b) - 29);
    require(json != NULL, "clock fault source JSON");
    if (clock_fault == 1)
        cJSON_DeleteItemFromObjectCaseSensitive(json, "accounting-time-ms");
    else if (clock_fault == 2)
        cJSON_DeleteItemFromObjectCaseSensitive(json, "server-time-ms");
    else if (clock_fault == 3)
    {
        cJSON_DeleteItemFromObjectCaseSensitive(json, "accounting-time-ms");
        discard cJSON_AddStringToObject(json, "accounting-time-ms", "18446744073709551616");
    }
    else if (clock_fault == 4)
        discard cJSON_AddStringToObject(json, "accounting-time-ms", "1"); /* decoded duplicate */
    else if (clock_fault == 5)
    {
        cJSON_DeleteItemFromObjectCaseSensitive(json, "server-time-ms");
        discard cJSON_AddStringToObject(json, "server_time_ms", "1000000");
    }
    else
    {
        cJSON_DeleteItemFromObjectCaseSensitive(json, "accounting-time-ms");
        discard cJSON_AddNumberToObject(json, "accounting-time-ms", 1.5);
    }
    clock_fault = 0;
    char *text  = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    const uint32_t length = (uint32_t) stringLength(text);
    b                     = sbufReserveSpace(b, 29 + length);
    sbufSetLength(b, 29 + length);
    uint32_t number = htonl(25 + length);
    memoryCopy(sbufGetMutablePtr(b), &number, 4);
    number = htonl(length);
    memoryCopy(sbufGetMutablePtr(b) + 25, &number, 4);
    memoryCopy(sbufGetMutablePtr(b) + 29, text, length);
    cJSON_free(text);
    return b;
}

static sbuf_t *faultUsageAck(sbuf_t *b)
{
    char     text[512];
    uint32_t length = sbufGetLength(b) - 29;
    require(length + 32 < sizeof(text), "ACK fault fixture exceeds scratch capacity");
    memoryCopy(text, (const uint8_t *) sbufGetRawPtr(b) + 29, length);
    text[length]         = '\0';
    size_t      at       = length - 1;
    const char *addition = ",\"needs-pull\":false";
    if (ack_fault == 1)
    {
        at       = length;
        addition = "!";
    }
    else if (ack_fault == 3 || ack_fault == 4)
    {
        const char *key   = ack_fault == 3 ? "\"epoch\":\"" : "\"digest\":\"";
        const char *value = strstr(text, key);
        require(value != NULL, "ACK fault field is absent");
        const char *end = strchr(value + strlen(key), '"');
        require(end != NULL, "ACK fault field is unterminated");
        at       = (size_t) (end - text);
        addition = "\\u0000other";
    }
    else if (ack_fault == 5)
        addition = ",\"extra\":\"\xff\"";
    const size_t extra = strlen(addition);
    memoryMove(text + at + extra, text + at, length - at);
    memoryCopy(text + at, addition, extra);
    length += (uint32_t) extra;
    b = sbufReserveSpace(b, 29 + length);
    require(sbufGetMaximumWriteableSize(b) >= 29 + length, "ACK fault buffer capacity");
    uint32_t number = htonl(25 + length);
    memoryCopy(sbufGetMutablePtr(b), &number, 4);
    number = htonl(length);
    memoryCopy(sbufGetMutablePtr(b) + 25, &number, 4);
    memoryCopy(sbufGetMutablePtr(b) + 29, text, length);
    sbufSetLength(b, 29 + length);
    ack_fault = 0;
    return b;
}

static void output(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard    t;
    const bool previous_clock = in_server;
    in_server                 = false;
    b                         = faultClockMetadata(b);
    b                         = authPageResponseFault(b);
    const uint8_t *bytes      = sbufGetRawPtr(b);
    const int      i          = owner(l);
    if (i < 0)
    {
        require(sbufGetLength(b) >= 29, "raw response was truncated");
        raw_response[lineGetWID(l)] = bytes[20];
        const uint32_t length       = min(sbufGetLength(b) - 29, (uint32_t) sizeof(raw_body[0]) - 1U);
        memoryCopy(raw_body[lineGetWID(l)], bytes + 29, length);
        raw_body[lineGetWID(l)][length] = 0;
        lineReuseBuffer(l, b);
        in_server = previous_clock;
        return;
    }
    if (sbufGetLength(b) > 29 && bytes[20] == kAuthenticationClientResponseTypeError && bytes[29] == '{')
    {
        cJSON       *proof = cJSON_ParseWithLength((const char *) bytes + 29, sbufGetLength(b) - 29);
        const cJSON *error = cJSON_GetObjectItemCaseSensitive(proof, "error");
        if (cJSON_IsString(error) && strcmp(error->valuestring, "usage-accounts-missing") == 0)
        {
            captured_sequence = UINT64_MAX; /* A proved rejection permits reconstruction at the same sequence. */
            if (missing_proof_fault != 0)
            {
                cJSON *field =
                    cJSON_GetObjectItemCaseSensitive(proof, missing_proof_fault == 1 ? "digest" : "checkpoint-digest");
                require(cJSON_IsString(field), "missing-account proof digest fixture");
                field->valuestring[0] = field->valuestring[0] == 'a' ? 'b' : 'a';
                missing_proof_fault   = 0;
                char          *text   = cJSON_PrintUnformatted(proof);
                const uint32_t length = (uint32_t) strlen(text);
                b                     = sbufReserveSpace(b, 29 + length);
                sbufSetLength(b, 29 + length);
                uint32_t number = htonl(25 + length);
                memoryCopy(sbufGetMutablePtr(b), &number, 4);
                number = htonl(length);
                memoryCopy(sbufGetMutablePtr(b) + 25, &number, 4);
                memoryCopy(sbufGetMutablePtr(b) + 29, text, length);
                cJSON_free(text);
                bytes = sbufGetRawPtr(b);
            }
        }
        cJSON_Delete(proof);
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
        in_server = previous_clock;
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
            in_server = previous_clock;
            return;
        }
        if (corrupt_ack > 0)
        {
            --corrupt_ack;
            sbufGetMutablePtr(b)[29] = '!';
        }
        if (ack_fault != 0)
            b = faultUsageAck(b);
    }
    if ((last_response == kAuthenticationClientResponseTypeSession && pause_before_session) ||
        (last_response == kAuthenticationClientResponseTypeOk && pause_before_ack))
    {
        pause_before_session = pause_before_ack = false;
        authenticationclientTunnelDownStreamPause(clients[i], l);
    }
    tunnelDownStreamPayload(clients[i], l, b);
    in_server = previous_clock;
}
static void serverPayload(line_t *l, sbuf_t *b)
{
    const bool previous = in_server;
    in_server           = true;
    tunnelUpStreamPayload(server, l, b);
    in_server = previous;
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
        if (captured_batch != NULL && sequence == captured_sequence && captured_owner == owner(l))
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
        captured_owner    = owner(l);
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
        ++page_requests;
        cJSON       *page     = cJSON_ParseWithLength((const char *) bytes + 77, sbufGetLength(b) - 77);
        const cJSON *cursor   = cJSON_GetObjectItemCaseSensitive(page, "cursor");
        const bool   initial  = cursor == NULL;
        const bool   final    = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(page, "validate"));
        uint64_t     position = initial ? 0 : strtoull(cursor->valuestring + 48, NULL, 16);
        cJSON_Delete(page);
        if (initial)
            ++pulls;
        if (position == hold_page_position || (final && hold_final_page))
        {
            hold_page_position = UINT64_MAX;
            hold_final_page    = false;
            require(held_request == NULL, "more than one held pagination request");
            held_request = b;
            return;
        }
        if (hold_pull && initial)
        {
            hold_pull = false;
            require(held_request == NULL, "more than one held pull");
            held_request = b;
            return;
        }
    }
    discard t;
    serverPayload(l, b);
}
static void pump(unsigned milliseconds)
{
    atomicAddU64(&now_us, (uint64_t) milliseconds * 1000);
    for (unsigned j = 0; j < 4; ++j)
        discard wloopProcessEvents(loops[0], 0);
}
static void retryConnection(unsigned client_index)
{
    const authenticationclient_tstate_t *ts  = state(client_index);
    const uint64_t                       now = authenticationclientLocalTimeMS();
    uint64_t                             due = max(ts->sync_retry_not_before_ms, ts->reconnect_due_ms);
    if (ts->stats_push_refused)
        due = max(due, ts->stats_retry_not_before_ms);
    require(due >= now && due - now <= UINT32_MAX, "fake retry deadline is not representable");
    pump((unsigned) (due - now));
}

static void setup(unsigned users)
{
    atomicStoreU64(&now_us, 100000000);
    atomicStoreU64(&server_wall_ms, 1000000);
    atomicStoreU64(&client_wall_ms, 7000000);
    in_server            = false;
    fail_server_rng_call = server_rng_calls = 0;
    clock_fault                             = 0;
    ack_fault                               = 0;
    captured_owner                          = -1;
    clients[0] = clients[1] = NULL;
    drop_before = drop_ack = corrupt_ack = drop_auth = pushes = pulls = 0;
    page_requests                                                     = 0;
    hold_page_position                                                = UINT64_MAX;
    hold_final_page                                                   = false;
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
        workers[i].buffer_pool = pools[i];
        workers[i].wios_pool   = wios[i];
        loops[i]               = wloopCreate(WLOOP_FLAG_AUTO_FREE, pools[i], i);
        workers[i].loop        = loops[i];
        loops[i]->status       = WLOOP_STATUS_RUNNING;
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
    in_server                  = true;
    server                     = authTestPeerCreate(client_size);
    in_server                  = false;
    authTestPeerPopulate(server, users);
    tunnelBind(transport, server);
    chain       = memoryCalloc(1, sizeof(*chain) + 2 * sizeof(generic_pool_t *));
    line_master = masterpoolCreateWithCapacity(16);
    for (unsigned i = 0; i < 2; ++i)
        chain->line_pools[i] = genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(
            line_master, sizeof(line_t) + client_size + authTestPeerLineSize() + 4096, 8);
}
static void startWithMultiplier(unsigned i, uint32_t multiplier)
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
    ts->traffic_multiplier    = multiplier;
    ts->name                  = stringDuplicate(i == 0 ? "edge-a" : "edge-b");
    ts->secret                = stringDuplicate("secret");
    ts->started               = true;
    ts->users_generation      = 1;
    ts->next_correlation_id   = 1;
    ts->reconnect_interval_ms = 10;
    ts->request_timeout_ms    = 1000;
    ts->max_pending_requests  = 64;
    ts->sync_max_users        = kAuthenticationDefaultSyncMaxUsers;
    ts->sync_max_bytes        = kAuthenticationDefaultSyncMaxBytes;
    authenticationclientOpenControlLine(t);
}
static void start(unsigned i)
{
    startWithMultiplier(i, kUserTrafficMultiplierScale);
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
    retryConnection(0);
    require(state(0)->pending_batch != NULL && authTestPeerStats(server, 42).traffic.u == 10,
            "repeated lost ACK charged twice");
    retryConnection(0);
    require(state(0)->pending_batch == NULL && local(0, true) == 10 && local(0, false) == 17,
            "ACK/pull lost post-snapshot traffic");
    require(authTestPeerFirstUse(server) == first_use, "duplicate changed first-use timestamp");
    authenticationclientRequestPush(clients[0]);
    pump(1);
    pump(1);
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
    pump(1);
    pump(1);
    require(held_request != NULL && state(0)->pending_batch != NULL, "push was not held");
    tunnelDownStreamPayload(clients[0], state(0)->control_line, sbufDuplicate(saved_ack));
    require(state(0)->pending_batch != NULL && local(0, true) == 20, "stale ACK settled the current batch");
    sbuf_t *pending = held_request;
    held_request    = NULL;
    serverPayload(state(0)->control_line, pending);
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
    serverPayload(state(0)->control_line, request);
    require(authTestPeerStats(server, 42).traffic.u == 27 && local(0, true) == 27, "coalesced push disappeared");
    teardown();
}

static void deliverHeldRequest(void)
{
    require(held_request != NULL, "no request to deliver");
    sbuf_t *request = held_request;
    held_request    = NULL;
    serverPayload(state(0)->control_line, request);
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
        require(! ts->pull_requested && ts->push_requested && pushes == i,
                "periodic pull duplicated a traversal or lost the waiting push");
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
    require(pushes == 0 && state(0)->progress_timer != NULL, "catch-up did not yield after capture");
    pump(1);
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

static void testPeriodicAndExplicitPullCoalescing(void)
{
    for (unsigned boundary = 0; boundary < 2; ++boundary)
        for (unsigned explicit_pull = 0; explicit_pull < 2; ++explicit_pull)
        {
            setup(257);
            start(0);
            authenticationclient_tstate_t *ts = state(0);
            ts->pull_interval_ms              = 1000;
            require(authenticationclientStartSyncTimer(clients[0]), "periodic pull timer creation failed");
            const uint64_t generation = ts->users_generation;
            const unsigned traversals = pulls;
            /* First response advertises a revision newer than the active cache.
             * Timer ticks must still join this unpublished traversal. */
            authTestPeerSetConfigRevision(server, ts->local_config_revision + 1);
            if (boundary == 0)
                hold_page_position = 128;
            else
                hold_final_page = true;
            authenticationclientRequestPull(clients[0]);
            require(held_request != NULL && ts->staging.active && ts->pull_in_flight && ! ts->pull_requested &&
                        ts->users_generation == generation,
                    "periodic coalescing traversal did not hold its publication barrier");
            for (unsigned tick = 0; tick < 5; ++tick)
            {
                ts->last_pull_sync_ms = getTickMS() - 1000;
                authenticationclientSyncTimerCallback(ts->sync_timer);
                require(! ts->pull_requested && pulls == traversals + 1 && ts->pending_batch == NULL,
                        "periodic tick latched another traversal or crossed the usage barrier");
            }
            if (explicit_pull)
            {
                authenticationclientRequestPull(clients[0]);
                authenticationclientRequestPull(clients[0]);
                ts->last_pull_sync_ms = getTickMS() - 1000;
                authenticationclientSyncTimerCallback(ts->sync_timer);
                require(ts->pull_requested, "periodic tick erased explicit pull demand");
            }
            deliverHeldRequest();
            pump(1);
            require(ts->users_generation == generation + 1 + explicit_pull && pulls == traversals + 1 + explicit_pull &&
                        ! ts->staging.active && ! ts->pull_requested && ! ts->pull_in_flight &&
                        ts->progress_timer == NULL,
                    "periodic/explicit demand installed an incorrect number of traversals");
            teardown();
        }
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
    sbuf_t *message = bufferpoolGetBestFit(lineGetBufferPool(l), 77 + length, 0);
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
    serverPayload(l, message);
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

static cJSON *serverApi(const char *operation, const char *request, enum api_result_e expected)
{
    const bool previous = in_server;
    in_server           = true;
    cJSON *body         = authTestPeerApi(server, operation, request, expected);
    in_server           = previous;
    return body;
}

static void serverEditToken(char token[49])
{
    cJSON       *body  = serverApi("get-user", "{\"id\":\"42\"}", kApiResultOk);
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(body, "edit_token");
    require(cJSON_IsString(value) && strlen(value->valuestring) == 48, "peer API edit token absent");
    memoryCopy(token, value->valuestring, 49);
    cJSON_Delete(body);
}

static cJSON *apiPatchWithToken(const char *token, const char *patch, const char *error)
{
    char   *before  = authTestPeerSnapshot(server);
    cJSON  *request = cJSON_CreateObject();
    discard cJSON_AddStringToObject(request, "id", "42");
    discard cJSON_AddStringToObject(request, "if_match", token);
    cJSON  *changes = cJSON_Parse(patch);
    require(cJSON_IsObject(changes), "invalid API patch fixture");
    discard cJSON_AddItemToObject(request, "patch", changes);
    char   *text = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);
    cJSON *response = serverApi("update-user", text, error == NULL ? kApiResultOk : kApiResultError);
    cJSON_free(text);
    char *after = authTestPeerSnapshot(server);
    if (error != NULL)
    {
        const cJSON *code =
            cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(response, "error"), "code");
        require(cJSON_IsString(code) && strcmp(code->valuestring, error) == 0 && strcmp(before, after) == 0,
                "API refusal changed users, indexes, revisions or producer checkpoints");
    }
    else
    {
        cJSON *old = cJSON_Parse(before), *current = cJSON_Parse(after);
        require(jsonUnsigned(current, "config-revision") == jsonUnsigned(old, "config-revision") + 1 &&
                    jsonUnsigned(response, "config_revision") == jsonUnsigned(current, "config-revision") &&
                    jsonUnsigned(current, "stats-revision") == jsonUnsigned(old, "stats-revision") &&
                    cJSON_Compare(cJSON_GetObjectItemCaseSensitive(current, "checkpoints"),
                                  cJSON_GetObjectItemCaseSensitive(old, "checkpoints"),
                                  true),
                "API patch changed accounting/checkpoint or did not increment configuration exactly once");
        cJSON_Delete(old);
        cJSON_Delete(current);
    }
    cJSON_free(before);
    cJSON_free(after);
    return response;
}

static cJSON *apiPatch(const char *patch, const char *error)
{
    char token[49];
    serverEditToken(token);
    return apiPatchWithToken(token, patch, error);
}

static void testApiProtocolPatchOrdering(void)
{
    setup(1);
    user_update_t initial = {.mask = kUserUpdateName | kUserUpdateStats, .name = "original", .stats.traffic.u = 100};
    authTestPeerSetUser(server, 42, &initial);
    authTestPeerPermissions(server, 0, true, true);
    start(0);
    uint8_t token[64];
    char    epoch[65], stale[49];
    authTestPeerCredentials(server, 0, token, epoch);
    line_t *line = lineCreate(chain->line_pools, 0);
    tunnelUpStreamInit(server, line);
    serverEditToken(stale);
    expectPatch(line, token, "{\"id\":42,\"name\":\"producer-name\"}", true);
    cJSON_Delete(apiPatchWithToken(stale, "{\"email\":\"stale@example.test\"}", "conflict"));
    cJSON *ack = apiPatch("{\"gid\":\"7\",\"limit\":{\"traffic\":{\"total\":\"1000\"}}}", NULL);
    require(jsonUnsigned(ack, "config_revision") == 3, "API did not follow real producer revision");
    memoryCopy(stale, cJSON_GetObjectItemCaseSensitive(ack, "edit_token")->valuestring, sizeof(stale));
    cJSON_Delete(ack);
    expectPatch(line, token, "{\"id\":42,\"email\":\"producer@example.test\"}", true);
    cJSON_Delete(apiPatchWithToken(stale, "{\"notes\":\"stale\"}", "conflict"));
    cJSON *user = authTestPeerUserJson(server, 42);
    require(
        jsonUnsigned(user, "gid") == 7 &&
            jsonUnsigned(cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(user, "limit"), "traffic"),
                         "total") == 1000 &&
            strcmp(cJSON_GetObjectItemCaseSensitive(user, "name")->valuestring, "producer-name") == 0 &&
            strcmp(cJSON_GetObjectItemCaseSensitive(user, "email")->valuestring, "producer@example.test") == 0,
        "API/producer sparse patches reset one another's omitted configuration");
    cJSON_Delete(user);

    serverEditToken(stale);
    traffic(0, 10);
    authenticationclientRequestPush(clients[0]);
    const uint64_t first_use = authTestPeerFirstUse(server), sequence = authTestPeerSequence(server, 0);
    cJSON_Delete(apiPatchWithToken(stale, "{\"notes\":\"after usage\"}", NULL));
    require(authTestPeerStats(server, 42).traffic.u == 110 && authTestPeerFirstUse(server) == first_use &&
                sequence == 1 && authTestPeerSequence(server, 0) == sequence,
            "statistics-only edit-token reuse changed newer usage or producer accounting");
    tunnelUpStreamFin(server, line);
    lineDestroy(line);
    teardown();
}

static cJSON *apiCreate(const char *request, const char *error)
{
    char  *before   = authTestPeerSnapshot(server);
    cJSON *response = serverApi("create-user", request, error == NULL ? kApiResultOk : kApiResultError);
    char  *after    = authTestPeerSnapshot(server);
    if (error != NULL)
    {
        const cJSON *code =
            cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(response, "error"), "code");
        require(cJSON_IsString(code) && strcmp(code->valuestring, error) == 0 && strcmp(before, after) == 0,
                "API creation refusal changed users, indexes, revisions or checkpoints");
    }
    else
    {
        cJSON       *old = cJSON_Parse(before), *current = cJSON_Parse(after);
        const cJSON *old_users = cJSON_GetObjectItemCaseSensitive(old, "users");
        const cJSON *new_users = cJSON_GetObjectItemCaseSensitive(current, "users");
        require(jsonUnsigned(current, "config-revision") == jsonUnsigned(old, "config-revision") + 1 &&
                    jsonUnsigned(response, "config_revision") == jsonUnsigned(current, "config-revision") &&
                    jsonUnsigned(current, "stats-revision") == jsonUnsigned(old, "stats-revision") &&
                    cJSON_GetArraySize(new_users) == cJSON_GetArraySize(old_users) + 1 &&
                    cJSON_Compare(cJSON_GetObjectItemCaseSensitive(current, "checkpoints"),
                                  cJSON_GetObjectItemCaseSensitive(old, "checkpoints"),
                                  true),
                "API creation changed accounting/checkpoints or did not publish exactly one account/revision");
        const cJSON *previous;
        cJSON_ArrayForEach(previous, old_users)
        {
            const cJSON *candidate;
            bool         found = false;
            cJSON_ArrayForEach(candidate, new_users)
            {
                if (jsonUnsigned(candidate, "id") == jsonUnsigned(previous, "id"))
                {
                    require(cJSON_Compare(previous, candidate, true), "API creation changed an existing account");
                    found = true;
                    break;
                }
            }
            require(found, "API creation removed an existing account");
        }
        cJSON_Delete(old);
        cJSON_Delete(current);
    }
    cJSON_free(before);
    cJSON_free(after);
    return response;
}

static void testApiProtocolCreationOrdering(void)
{
    setup(1);
    user_update_t initial = {.mask = kUserUpdateName | kUserUpdateStats, .name = "original", .stats.traffic.u = 100};
    authTestPeerSetUser(server, 42, &initial);
    authTestPeerPermissions(server, 0, true, true);
    start(0);
    uint8_t token[64];
    char    epoch[65], old_token[49];
    authTestPeerCredentials(server, 0, token, epoch);
    serverEditToken(old_token);
    line_t *line = lineCreate(chain->line_pools, 0);
    tunnelUpStreamInit(server, line);

    const char first[] = "{\"id\":\"99\",\"password\":\"api-created-secret\",\"config\":{\"name\":\"created\"}}";
    cJSON     *ack     = apiCreate(first, NULL);
    require(jsonUnsigned(ack, "config_revision") == 2, "creation did not publish its own revision");
    cJSON_Delete(ack);
    cJSON_Delete(apiPatchWithToken(old_token, "{\"notes\":\"stale\"}", "conflict"));
    cJSON_Delete(apiCreate(first, "id_exists"));
    cJSON_Delete(apiCreate("{\"id\":\"100\",\"password\":\"api-created-secret\"}", "credentials_exist"));
    char      *before      = authTestPeerSnapshot(server);
    const char duplicate[] = "{\"id\":\"99\",\"password\":\"producer-replacement\"}";
    rawRequest(line, token, kAuthenticationClientRequestTypeAddNewUser, duplicate, sizeof(duplicate) - 1);
    char *after = authTestPeerSnapshot(server);
    require(raw_response[0] == 255 && strcmp(raw_body[0], "user-id-exists") == 0 && strcmp(before, after) == 0,
            "producer add replaced an API-created identity or changed revision/checkpoint");
    cJSON_free(before);
    cJSON_free(after);

    expectPatch(line, token, "{\"id\":99,\"notes\":\"later producer edit\"}", true);
    ack = apiCreate("{\"id\":\"100\",\"password\":\"second-created-secret\"}", NULL);
    require(jsonUnsigned(ack, "config_revision") == 4,
            "independent token-free creation did not follow the real producer edit");
    cJSON_Delete(ack);
    cJSON *created = authTestPeerUserJson(server, 99);
    require(strcmp(cJSON_GetObjectItemCaseSensitive(created, "notes")->valuestring, "later producer edit") == 0,
            "later independent creation erased a producer edit");
    cJSON_Delete(created);

    traffic(0, 10);
    authenticationclientRequestPush(clients[0]);
    const uint64_t first_use = authTestPeerFirstUse(server), sequence = authTestPeerSequence(server, 0);
    ack = apiCreate("{\"id\":\"101\",\"password\":\"third-created-secret\"}", NULL);
    require(jsonUnsigned(ack, "config_revision") == 5 && sequence == 1 && authTestPeerSequence(server, 0) == sequence &&
                authTestPeerStats(server, 42).traffic.u == 110 && authTestPeerFirstUse(server) == first_use,
            "stats-only work prevented creation or creation changed producer accounting");
    cJSON_Delete(ack);
    tunnelUpStreamFin(server, line);
    lineDestroy(line);
    teardown();
}

static void testApiCreationDuringOfflineCatchup(void)
{
    setup(1);
    user_update_t initial = {
        .mask = kUserUpdateStats | kUserUpdateTimeInfo, .stats.traffic.u = 100, .timeinfo.created_at_ms = 123};
    authTestPeerSetUser(server, 42, &initial);
    start(0);
    user_ip_key_t ip = {.type = 4, .bytes = {192, 0, 2, 1}};
    require(usersTryAdmitConnectionByIdentifier(state(0)->users, 42, &ip, getTimeOfDayMS()) == kUserAdmissionOk,
            "creation refresh reservation setup failed");
    traffic(0, 10);
    user_t        *existing = usersLookupByIdentifier(state(0)->users, 42);
    const uint64_t origin   = existing->client_time.first_report_ms;
    drop_ack                = 1;
    authenticationclientRequestPush(clients[0]);
    const uint64_t first_use = authTestPeerFirstUse(server);
    require(! authenticationclientIsReady(clients[0]) && state(0)->pending_batch != NULL &&
                authTestPeerStats(server, 42).traffic.u == 110,
            "creation lost-ACK/offline setup failed");
    cJSON_Delete(apiCreate("{\"id\":\"99\",\"password\":\" account-api-created \"}", NULL));
    user_handle_t handle = {0};
    require(usersLookupByIdentifier(state(0)->users, 99) == NULL &&
                ! authenticationclientGetUserByPassword(clients[0], " account-api-created ", &handle) &&
                ! userHandleIsValid(&handle) && state(0)->pending_batch != NULL && local(0, false) == 110,
            "offline client admitted an unknown account or creation settled its pending debt");
    traffic(0, 7);
    pump(10);
    pump(1);
    pump(1);
    require(state(0)->pending_batch == NULL && state(0)->catchup_entries_count == 0 && local(0, true) == 117 &&
                local(0, false) == 117 && authTestPeerStats(server, 42).traffic.u == 117 &&
                authTestPeerSequence(server, 0) == 2 && authTestPeerFirstUse(server) == first_use,
            "creation refresh lost pending/offline traffic or replayed it twice");
    require(authenticationclientGetUserByPassword(clients[0], " account-api-created ", &handle) &&
                handle.user_id == 99 &&
                ! authenticationclientGetUserByPassword(clients[0], "account-api-created", &handle),
            "normal refresh omitted new credentials or normalized their exact bytes");
    user_t *fresh = usersLookupByIdentifier(state(0)->users, 99);
    require(fresh != NULL && fresh->timeinfo.first_usage_at_ms == 0 && fresh->stats.traffic.u == 0 &&
                fresh->stats.traffic.d == 0 && fresh->runtime.active_cons_out == 0,
            "creation/read/synchronization counted as fresh-account traffic");
    existing = usersLookupByIdentifier(state(0)->users, 42);
    require(existing->runtime.active_cons_out == 1 && existing->runtime.ip_usage_count == 1 &&
                existing->timeinfo.created_at_ms == 123 && existing->client_time.first_report_ms == origin &&
                existing->client_time.observation_acked,
            "creation refresh lost existing runtime reservation, metadata or accounting observation");
    usersReleaseConnectionByIdentifier(state(0)->users, 42, &ip);

    cJSON_Delete(apiCreate("{\"id\":\"100\",\"password\":\"connected-api-created\"}", NULL));
    require(usersLookupByIdentifier(state(0)->users, 100) == NULL,
            "API acknowledgement implied immediate client refresh");
    authenticationclientRequestPull(clients[0]);
    require(authenticationclientGetUserByPassword(clients[0], "connected-api-created", &handle) &&
                handle.user_id == 100 &&
                usersLookupByIdentifier(state(0)->users, 100)->timeinfo.first_usage_at_ms == 0 &&
                authTestPeerStats(server, 42).traffic.u == 117 && local(0, false) == 117,
            "connected ordinary refresh omitted creation or changed existing/new accounting");
    teardown();
}

static void testConfigRevisionExhaustion(void)
{
    for (unsigned api_last = 0; api_last < 2; ++api_last)
    {
        setup(1);
        authTestPeerPermissions(server, 0, true, true);
        start(0);
        uint8_t token[64];
        char    epoch[65];
        authTestPeerCredentials(server, 0, token, epoch);
        line_t *line = lineCreate(chain->line_pools, 0);
        tunnelUpStreamInit(server, line);
        authTestPeerSetConfigRevision(server, UINT64_MAX - 1);
        if (api_last)
        {
            cJSON *ack = apiPatch("{\"notes\":\"last edit\"}", NULL);
            require(jsonUnsigned(ack, "config_revision") == UINT64_MAX, "API rejected final valid revision");
            cJSON_Delete(ack);
        }
        else
            expectPatch(line, token, "{\"id\":42,\"notes\":\"last edit\"}", true);
        cJSON_Delete(apiPatch("{\"notes\":\"must refuse\"}", "revision_exhausted"));
        expectPatch(line, token, "{\"id\":42,\"notes\":\"must refuse\"}", false);
        require(strcmp(raw_body[0], "revision-exhausted") == 0, "protocol update did not report revision exhaustion");
        char      *before = authTestPeerSnapshot(server);
        const char add[]  = "{\"id\":\"99\",\"password\":\"terminal-new-account\"}";
        rawRequest(line, token, kAuthenticationClientRequestTypeAddNewUser, add, sizeof(add) - 1);
        char *after = authTestPeerSnapshot(server);
        require(raw_response[0] == 255 && strcmp(raw_body[0], "revision-exhausted") == 0 && strcmp(before, after) == 0,
                "protocol add mutated accounts or revision after exhaustion");
        cJSON_free(before);
        cJSON_free(after);
        tunnelUpStreamFin(server, line);
        lineDestroy(line);
        teardown();
    }
}

static void testApiEditDuringOfflineCatchup(void)
{
    setup(1);
    user_update_t initial = {.mask                   = kUserUpdateName | kUserUpdateStats | kUserUpdateTimeInfo,
                             .name                   = "original",
                             .stats.traffic.u        = 100,
                             .timeinfo.created_at_ms = 123};
    authTestPeerSetUser(server, 42, &initial);
    start(0);
    user_ip_key_t ip = {.type = 4, .bytes = {192, 0, 2, 1}};
    require(usersTryAdmitConnectionByIdentifier(state(0)->users, 42, &ip, getTimeOfDayMS()) == kUserAdmissionOk,
            "API refresh reservation setup failed");
    traffic(0, 10);
    user_t        *user   = usersLookupByIdentifier(state(0)->users, 42);
    const uint64_t origin = user->client_time.first_report_ms;
    drop_ack              = 1;
    authenticationclientRequestPush(clients[0]);
    const uint64_t first_use = authTestPeerFirstUse(server);
    require(first_use != 0 && state(0)->pending_batch != NULL && authTestPeerStats(server, 42).traffic.u == 110,
            "API lost-ACK setup failed");
    cJSON_Delete(apiPatch("{\"name\":\"after-api\",\"time\":{\"expire_after_first_usage_ms\":\"9000\"}}", NULL));
    require(authTestPeerStats(server, 42).traffic.u == 110 && authTestPeerFirstUse(server) == first_use,
            "API edit reset already committed traffic or first-use observation");
    traffic(0, 7);
    pump(10);
    pump(1);
    pump(1);
    require(state(0)->pending_batch == NULL && state(0)->catchup_entries_count == 0 && local(0, true) == 117 &&
                local(0, false) == 117 && authTestPeerStats(server, 42).traffic.u == 117 &&
                authTestPeerSequence(server, 0) == 2 && authTestPeerFirstUse(server) == first_use,
            "API edit plus replay/refresh lost offline catch-up or charged the same batch twice");
    user = usersLookupByIdentifier(state(0)->users, 42);
    require(strcmp(user->name, "after-api") == 0 && user->runtime.active_cons_out == 1 &&
                user->runtime.ip_usage_count == 1 && user->timeinfo.created_at_ms == 123 &&
                user->timeinfo.expire_after_first_usage_ms == 9000 && user->client_view_expiry_valid &&
                user->client_time.first_report_ms == origin && user->client_time.observation_acked,
            "API refresh lost configuration, runtime reservation, observation or expiry projection");
    usersReleaseConnectionByIdentifier(state(0)->users, 42, &ip);
    require(user->runtime.active_cons_out == 0, "API-refreshed reservation did not release");
    teardown();
}

static cJSON *apiPasswordWithToken(const char *token, const char *password, const char *error)
{
    char   *before  = authTestPeerSnapshot(server);
    cJSON  *request = cJSON_CreateObject();
    discard cJSON_AddStringToObject(request, "id", "42");
    discard cJSON_AddStringToObject(request, "if_match", token);
    discard cJSON_AddStringToObject(request, "password", password);
    char   *text = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);
    cJSON *response = serverApi("change-user-password", text, error == NULL ? kApiResultOk : kApiResultError);
    cJSON_free(text);
    char *after = authTestPeerSnapshot(server);
    if (error != NULL)
    {
        const cJSON *code =
            cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(response, "error"), "code");
        require(cJSON_IsString(code) && strcmp(code->valuestring, error) == 0 && strcmp(before, after) == 0,
                "password refusal changed account, revision or accounting checkpoints");
    }
    else
    {
        cJSON *old = cJSON_Parse(before), *current = cJSON_Parse(after);
        require(jsonUnsigned(current, "config-revision") == jsonUnsigned(old, "config-revision") + 1 &&
                    jsonUnsigned(response, "config_revision") == jsonUnsigned(current, "config-revision") &&
                    jsonUnsigned(current, "stats-revision") == jsonUnsigned(old, "stats-revision") &&
                    cJSON_Compare(cJSON_GetObjectItemCaseSensitive(current, "checkpoints"),
                                  cJSON_GetObjectItemCaseSensitive(old, "checkpoints"),
                                  true),
                "password change advanced accounting/checkpoints or omitted its configuration revision");
        cJSON *old_users = cJSON_GetObjectItemCaseSensitive(old, "users");
        cJSON *new_users = cJSON_GetObjectItemCaseSensitive(current, "users");
        require(cJSON_GetArraySize(old_users) == 1 && cJSON_GetArraySize(new_users) == 1,
                "password change altered the account collection");
        cJSON_DeleteItemFromObjectCaseSensitive(cJSON_GetArrayItem(old_users, 0), "password");
        cJSON_DeleteItemFromObjectCaseSensitive(cJSON_GetArrayItem(new_users, 0), "password");
        require(cJSON_Compare(old_users, new_users, true), "password change altered noncredential account values");
        cJSON_Delete(old);
        cJSON_Delete(current);
    }
    cJSON_free(before);
    cJSON_free(after);
    return response;
}

static void requireClientPassword(unsigned client, const char *accepted, const char *rejected)
{
    user_handle_t handle;
    require(authenticationclientGetUserByPassword(clients[client], accepted, &handle) && handle.user_id == 42 &&
                ! authenticationclientGetUserByPassword(clients[client], rejected, &handle),
            "client credential cache differs from its refresh schedule");
}

static void testApiPasswordDuringOfflineCatchup(void)
{
    setup(1);
    user_update_t initial = {.mask                                 = kUserUpdateStats | kUserUpdateTimeInfo,
                             .stats.traffic.u                      = 100,
                             .timeinfo.created_at_ms               = 123,
                             .timeinfo.expire_after_first_usage_ms = 9000};
    authTestPeerSetUser(server, 42, &initial);
    start(0);
    start(1);
    user_handle_t handles[2];
    user_ip_key_t ips[2] = {{.type = 4, .bytes = {192, 0, 2, 1}}, {.type = 4, .bytes = {192, 0, 2, 2}}};
    for (unsigned i = 0; i < 2; ++i)
        require(authenticationclientGetUserByPassword(clients[i], "account-0", &handles[i]) &&
                    authenticationclientUserTryAdmitConnection(clients[i], &handles[i], &ips[i], 100000) ==
                        kUserAdmissionOk,
                "password refresh reservation setup failed");

    traffic(0, 10);
    user_t        *user        = usersLookupByIdentifier(state(0)->users, 42);
    const uint64_t observation = user->client_time.first_report_ms, origin = user->client_time.first_local_ms;
    const uint64_t expiry = user->client_view_expires_at_ms;
    drop_ack              = 1;
    authenticationclientRequestPush(clients[0]);
    const uint64_t first_use = authTestPeerFirstUse(server);
    require(! authenticationclientIsReady(clients[0]) && state(0)->pending_batch != NULL &&
                authTestPeerStats(server, 42).traffic.u == 110 && authTestPeerSequence(server, 0) == 1,
            "password change lost-ACK setup failed");
    state(1)->reconnect_interval_ms = 30;
    disconnect(1);
    traffic(1, 5);

    char token[49];
    serverEditToken(token);
    cJSON_Delete(apiPasswordWithToken(token, " rotated offline credential ", NULL));
    cJSON_Delete(apiPasswordWithToken(token, "must not replace", "conflict"));
    for (unsigned i = 0; i < 2; ++i)
        requireClientPassword(i, "account-0", " rotated offline credential ");
    traffic(0, 7);
    traffic(1, 3);
    pump(10);
    pump(1);
    pump(1);
    require(state(0)->pending_batch == NULL && state(0)->catchup_entries_count == 0 && local(0, true) == 117 &&
                local(0, false) == 117 && authTestPeerStats(server, 42).traffic.u == 117 &&
                authTestPeerSequence(server, 0) == 2 && authTestPeerSequence(server, 1) == 0 &&
                authTestPeerFirstUse(server) == first_use,
            "password rotation lost pending/offline traffic or charged exact replay twice");
    requireClientPassword(0, " rotated offline credential ", "account-0");
    requireClientPassword(1, "account-0", " rotated offline credential ");
    user = usersLookupByIdentifier(state(0)->users, 42);
    require(user->runtime.active_cons_out == 1 && user->runtime.ip_usage_count == 1 &&
                user->timeinfo.created_at_ms == 123 && user->client_time.first_report_ms == observation &&
                user->client_time.first_local_ms == origin && user->client_time.observation_acked &&
                user->client_view_expiry_valid && user->client_view_expires_at_ms <= expiry,
            "password refresh lost reservation, first-use origin/ACK or extended expiry");
    require(! authenticationclientUserAccountTraffic(clients[0], &handles[0], 2, 0, 100012),
            "existing connection stopped accounting after credential refresh");
    authenticationclientRequestPush(clients[0]);
    require(authTestPeerStats(server, 42).traffic.u == 119, "post-refresh existing traffic was lost");
    pump(20);
    pump(1);
    pump(1);
    requireClientPassword(1, " rotated offline credential ", "account-0");
    require(authTestPeerStats(server, 42).traffic.u == 127 && authTestPeerSequence(server, 1) == 1 &&
                authTestPeerFirstUse(server) == first_use && state(1)->pending_batch == NULL,
            "later client refresh lost offline debt or changed canonical first use");
    for (unsigned i = 0; i < 2; ++i)
    {
        authenticationclientRequestPull(clients[i]);
        user = usersLookupByIdentifier(state(i)->users, 42);
        require(local(i, false) == 127 && local(i, true) == 127 && user->runtime.active_cons_out == 1 &&
                    user->runtime.ip_usage_count == 1 && user->client_time.observation_acked,
                "different refresh schedules failed to converge accounting/reservations");
        authenticationclientUserReleaseConnection(clients[i], &handles[i], &ips[i]);
        require(user->runtime.active_cons_out == 0 && user->runtime.ip_usage_count == 0,
                "pre-rotation handle failed to release its migrated reservation");
    }
    teardown();
}

static void testApiPasswordDuringHeldRefresh(void)
{
    setup(1);
    user_update_t initial = {.mask                                 = kUserUpdateStats | kUserUpdateTimeInfo,
                             .stats.traffic.u                      = 100,
                             .timeinfo.created_at_ms               = 123,
                             .timeinfo.expire_after_first_usage_ms = 9000};
    authTestPeerSetUser(server, 42, &initial);
    start(0);
    start(1);
    user_handle_t handle;
    require(authenticationclientGetUserByPassword(clients[0], "account-0", &handle) &&
                authenticationclientUserTryAdmitConnection(clients[0], &handle, NULL, 100000) == kUserAdmissionOk,
            "held password refresh reservation failed");
    hold_pull = true;
    authenticationclientRequestPull(clients[0]);
    require(held_request != NULL && state(0)->pull_in_flight, "password refresh was not held");
    traffic(0, 9);
    const user_t  *before      = usersLookupByIdentifier(state(0)->users, 42);
    const uint64_t observation = before->client_time.first_report_ms, origin = before->client_time.first_local_ms;
    authenticationclientRequestPush(clients[0]);
    require(state(0)->push_requested && authTestPeerStats(server, 42).traffic.u == 100,
            "traffic overtook the held refresh");
    char token[49];
    serverEditToken(token);
    cJSON_Delete(apiPasswordWithToken(token, "held-refresh-credential", NULL));
    requireClientPassword(0, "account-0", "held-refresh-credential");
    requireClientPassword(1, "account-0", "held-refresh-credential");
    deliverHeldRequest();
    pump(1);
    pump(1);
    requireClientPassword(0, "held-refresh-credential", "account-0");
    requireClientPassword(1, "account-0", "held-refresh-credential");
    require(authTestPeerStats(server, 42).traffic.u == 109 && authTestPeerSequence(server, 0) == 1 &&
                local(0, false) == 109 && state(0)->pending_batch == NULL,
            "credential refresh lost traffic produced while the pull was in flight");
    user_t *user = usersLookupByIdentifier(state(0)->users, 42);
    require(user->client_time.first_report_ms == observation && user->client_time.first_local_ms == origin &&
                user->client_time.observation_acked && user->runtime.active_cons_out == 1 &&
                user->timeinfo.created_at_ms == 123 && user->client_view_expiry_valid,
            "held credential refresh lost first-use evidence, reservation or expiry projection");
    traffic(1, 4);
    authenticationclientRequestPull(clients[1]);
    authenticationclientRequestPush(clients[1]);
    pump(1);
    pump(1);
    requireClientPassword(1, "held-refresh-credential", "account-0");
    require(authTestPeerStats(server, 42).traffic.u == 113 && authTestPeerSequence(server, 1) == 1,
            "later connected refresh lost its pending traffic");
    require(! authenticationclientUserShouldClose(clients[0], &handle, 100004),
            "credential rotation revoked an otherwise eligible existing connection");
    authenticationclientUserReleaseConnection(clients[0], &handle, NULL);
    user = usersLookupByIdentifier(state(0)->users, 42);
    require(user->runtime.active_cons_out == 0, "held-refresh reservation failed to release by its original handle");
    teardown();
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
    pump(1);
    pump(1);
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
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"up\":1,\"down\":0,\"first-usage-at-ms\":1}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"down\":0,\"first-usage-at-ms\":1}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"first-usage-at-ms\":1}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":0}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":-1}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":1.0}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":1e0}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":"
        "\"18446744073709551616\"}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":null}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":1,\"first-"
        "usage-at-m\\u0073\":1}]}",

        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":1}],"
        "\"speed\":5}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":1,\"ips\":1}]"
        "}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":1},"
        "{\"id\":43,\"up\":1,\"down\":0,\"first-usage-at-ms\":1,\"connections-out\":1}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":1,\"first-"
        "usage-at-ms\":1}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":1,"
        "\"traffic\":{\"up\":100}}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-"
        "ms\":1}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"seq\\u0075ence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-"
        "at-ms\":1}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"\\u0069d\":42,\"up\":1,\"down\":0,\"first-usage-at-"
        "ms\":1}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":1}]} "
        "trailing",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1.0,\"down\":0,\"first-usage-at-ms\":1}]}",
        "{\"epoch\":\"%s\",\"sequence\":1e0,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":1}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":1},"
        "{\"id\":43,\"up\":0,\"down\":0,\"first-usage-at-ms\":0}]}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":1}],"
        "\"other\":\"\\u0000\"}",
        "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":1}],"
        "\"other\":\"\xed\xa0\x80\"}"};
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
    snprintf(text,
             sizeof(text),
             "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":3,\"down\":0,\"first-usage-at-ms\":1}]}",
             epoch);
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
    before = authTestPeerSnapshot(server);
    const char *removed =
        "{\"id\":42,\"password\":\"account-0\",\"stats\":{\"traffic\":{\"up\":99,\"down\":0,\"first-usage-at-ms\":1}}}";
    rawRequest(line, token, 8, removed, (uint32_t) stringLength(removed));
    after = authTestPeerSnapshot(server);
    require(raw_response[0] == 255 && stringCompare(raw_body[0], "unknown-request-type") == 0 &&
                stringCompare(before, after) == 0,
            "removed raw traffic opcode remained active");
    cJSON_free(before);
    cJSON_free(after);
    snprintf(text,
             sizeof(text),
             "{\"epoch\":\"%s\",\"sequence\":2,\"users\":[{\"id\":42,\"up\":\"18446744073709551615\",\"down\":0,"
             "\"first-usage-at-ms\":1}]}",
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
    snprintf(text,
             sizeof(text),
             "{\"epoch\":\"%s\",\"sequence\":3,\"users\":[{\"id\":43,\"up\":0,\"down\":0,\"first-usage-at-ms\":"
             "\"18446744073709551615\"}]}",
             epoch);
    before             = authTestPeerSnapshot(server);
    cJSON *before_json = cJSON_Parse(before);
    rawBatch(line, token, text);
    after             = authTestPeerSnapshot(server);
    cJSON *after_json = cJSON_Parse(after);
    cJSON *reported   = authTestPeerUserJson(server, 43);
    require(raw_response[0] == 0 && authTestPeerSequence(server, 0) == 3 &&
                jsonUnsigned(after_json, "stats-revision") == jsonUnsigned(before_json, "stats-revision") + 1 &&
                jsonUnsigned(after_json, "config-revision") == jsonUnsigned(before_json, "config-revision") &&
                jsonUnsigned(cJSON_GetObjectItemCaseSensitive(reported, "time"), "first-usage-at-ms") == 1000000 &&
                authTestPeerStats(server, 43).traffic.u == 0,
            "metadata-only future observation was not clamped/accepted exactly once");
    cJSON_Delete(before_json);
    cJSON_Delete(after_json);
    cJSON_Delete(reported);
    cJSON_free(before);
    cJSON_free(after);
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
    const char *entries[] = {"{\"id\":42,\"up\":20,\"down\":0,\"first-usage-at-ms\":1}",
                             "{\"id\":42,\"up\":5,\"down\":0,\"first-usage-at-ms\":1},{\"id\":999,\"up\":1,\"down\":0,"
                             "\"first-usage-at-ms\":1}",
                             "{\"id\":42,\"up\":5,\"down\":0,\"first-usage-at-ms\":1},{\"id\":42,\"up\":1,\"down\":0,"
                             "\"first-usage-at-ms\":1}"};
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
                 "{\"epoch\":\"%s\",\"sequence\":%" PRIu64
                 ",\"users\":[{\"id\":42,\"up\":1,\"down\":0,\"first-usage-at-ms\":1}]}",
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
    require(authenticationclientRegisterApi(clients[0]), "catch-up status registration failed");
    disconnect(0);
    for (size_t i = 0; i < usersCount(state(0)->users); ++i)
        discard userAccountTraffic(usersGetAt(state(0)->users, i), 1, 0, 0, NULL);
    hold_pull = true;
    pump(10);
    require(held_request != NULL, "reconnect required refresh was not held");
    discard userAccountTraffic(usersLookupByIdentifier(state(0)->users, 42), 1, 0, 0, NULL);
    deliverHeldRequest();
    require(state(0)->catchup_entries_count == 4097 && state(0)->progress_timer != NULL && pushes == 0,
            "reconnect failed to capture progress through initial refresh or did not yield");
    requireSyncPhase("catchup_pending");
    refuse_snapshot = true;
    pump(1);
    require(! refuse_snapshot && pushes == 0 && state(0)->progress_timer != NULL && local(0, true) == 0,
            "snapshot refusal lost catch-up progress trigger or advanced baseline");
    requireSyncPhase("catchup_pending");
    hold_push = true;
    pump(1);
    require(held_request != NULL && state(0)->pending_entries_count == 4096, "bounded catch-up batch not held");
    discard userAccountTraffic(usersLookupByIdentifier(state(0)->users, 42), 10, 0, 0, NULL);
    discard userAccountTraffic(usersLookupByIdentifier(state(0)->users, 42 + 4096), 1, 0, 0, NULL);
    /* Another producer changes the aggregate while this pass owes relative
     * amounts. No full second-client pull is needed for the raw producer. */
    line_t *other = lineCreate(chain->line_pools, 0);
    tunnelUpStreamInit(server, other);
    uint8_t    token[64] = {0};
    const char enroll[]  = "{\"name\":\"edge-b\",\"secret\":\"secret\"}";
    rawRequest(other, token, kAuthenticationClientRequestTypeAuthenticate, enroll, sizeof(enroll) - 1);
    char epoch[65], text[256];
    authTestPeerCredentials(server, 1, token, epoch);
    snprintf(text,
             sizeof(text),
             "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":7,\"down\":0,\"first-usage-at-ms\":1}]}",
             epoch);
    rawBatch(other, token, text);
    require(raw_response[0] == 0, "other producer contribution");
    tunnelUpStreamFin(server, other);
    lineDestroy(other);
    deliverHeldRequest();
    require(usersLookupByIdentifier(state(0)->users, 42)->client_time.observation_acked &&
                ! usersLookupByIdentifier(state(0)->users, 42 + 4096)->client_time.observation_acked,
            "ACK cleared an observation outside its bounded snapshot");
    requireSyncPhase("refresh_required");
    pump(1); /* required post-ACK refresh */
    require(state(0)->catchup_entries_count == 1 && state(0)->catchup_entries[0].id == 42 + 4096 &&
                state(0)->catchup_entries[0].delta.u == 1,
            "partial ACK did not compact settled debt while retaining unsent catch-up");
    requireSyncPhase("catchup_pending");
    discard userAccountTraffic(usersLookupByIdentifier(state(0)->users, 42), 100, 0, 0, NULL);
    pump(1); /* remaining captured user, despite continuing hot-account traffic */
    require(authTestPeerSequence(server, 0) == 2 && state(0)->pending_batch == NULL &&
                state(0)->catchup_entries_count == 0,
            "bounded reconnect catch-up did not finish");
    require(authTestPeerStats(server, 42).traffic.u == 9 && local(0, false) == 119 && local(0, true) == 9,
            "aggregate rebase corrupted relative capture or consumed post-cut traffic");
    for (uint64_t id = 43; id < 42 + 4096; ++id)
        require(authTestPeerStats(server, id).traffic.u == 1, "subset ACK advanced unsent users or lost their usage");
    require(authTestPeerStats(server, 42 + 4096).traffic.u == 2, "later captured user starved");
    pump(10);
    require(authTestPeerSequence(server, 0) == 2, "catch-up chased post-cut traffic indefinitely");
    requireSyncPhase("idle");
    teardown();
}
static void testBatchConstructionRefusal(void)
{
    for (unsigned kind = 0; kind < 1; ++kind)
    {
        setup(1);
        start(0);
        traffic(0, 1);
        refuse_snapshot = true;
        authenticationclientRequestPush(clients[0]);
        require(state(0)->pending_batch == NULL && local(0, true) == 0 && local(0, false) == 1,
                "construction refusal lost traffic or advanced baseline");
        require(! refuse_snapshot, "construction refusal was not reached");
        authenticationclientRequestPush(clients[0]);
        require(authTestPeerStats(server, 42).traffic.u == 1, "refusal prevented a later valid batch");
        teardown();
    }
}
static void testCachedAdmissionAndRejection(void)
{
    setup(1);
    hold_pull = true;
    start(0);
    require(! authenticationclientCanAuthenticate(clients[0]), "unloaded cache admitted");
    user_handle_t handle = {.generation = 1, .user_id = 42};
    require(! authenticationclientGetUserByPassword(clients[0], "account-0", &handle) && ! userHandleIsValid(&handle),
            "lookup bypassed initial cache policy");
    deliverHeldRequest();
    require(authenticationclientCanAuthenticate(clients[0]), "loaded cache unavailable");
    require(authenticationclientGetUserByPassword(clients[0], "account-0", &handle), "loaded lookup");
    disconnect(0);
    require(authenticationclientCanAuthenticate(clients[0]) && ! authenticationclientIsReady(clients[0]) &&
                authenticationclientGetUserByPassword(clients[0], "account-0", &handle),
            "ordinary outage blocked cache");
    user_ip_key_t ip = {.type = 4, .bytes = {192, 0, 2, 1}};
    require(authenticationclientUserTryAdmitConnection(clients[0], &handle, &ip, 100000) == kUserAdmissionOk,
            "offline reservation failed");
    memoryFree(state(0)->secret);
    state(0)->secret = stringDuplicate("wrong");
    pump(10);
    require(state(0)->auth_rejected && ! authenticationclientCanAuthenticate(clients[0]),
            "explicit rejection not latched");
    authenticationclient_status_t rejection_status;
    authenticationclientStatusSnapshot(clients[0], false, 0, 0, &rejection_status);
    require(rejection_status.users_loaded && ! rejection_status.can_authenticate &&
                rejection_status.blocking_reason == kAuthenticationClientBlockCredentialRejected &&
                rejection_status.last_failure == kAuthenticationClientFailureCredentialRejected,
            "status lost rejection history or conflated it with cache presence");
    require(! authenticationclientGetUserByPassword(clients[0], "account-0", &handle) && ! userHandleIsValid(&handle),
            "lookup bypassed sticky rejection");
    userHandleSet(&handle, state(0)->users_generation, 42);
    require(authenticationclientUserTryAdmitConnection(clients[0], &handle, &ip, 100010) == kUserAdmissionInvalid,
            "admission bypassed sticky rejection");
    require(! authenticationclientUserAccountTraffic(clients[0], &handle, 3, 0, 100010) && local(0, false) == 3,
            "credential rejection stopped existing accounting");
    authenticationclientUserReleaseConnection(clients[0], &handle, &ip);
    require(usersLookupByIdentifier(state(0)->users, 42)->runtime.active_cons_out == 0,
            "blocked admission prevented reservation release");
    memoryFree(state(0)->secret);
    state(0)->secret = stringDuplicate("secret");
    drop_auth        = 1;
    pump(1000);
    require(state(0)->auth_rejected, "lost authorization reply cleared rejection");
    pump(2000);
    require(! state(0)->auth_rejected && authenticationclientCanAuthenticate(clients[0]),
            "validated authorization did not clear block");
    /* Old correlated Authenticate id cannot revoke a newly authorized cache. */
    sbuf_t    *stale    = sbufDuplicate(saved_session);
    const char denial[] = "authentication-failed";
    sbufSetLength(stale, 29 + sizeof(denial) - 1);
    sbufGetMutablePtr(stale)[20] = 255;
    uint32_t number              = htonl(25 + sizeof(denial) - 1);
    memoryCopy(sbufGetMutablePtr(stale), &number, 4);
    number = htonl(sizeof(denial) - 1);
    memoryCopy(sbufGetMutablePtr(stale) + 25, &number, 4);
    memoryCopy(sbufGetMutablePtr(stale) + 29, denial, sizeof(denial) - 1);
    const authenticationclient_failure_t failure_before_stale      = state(0)->last_failure;
    const uint64_t                       failure_time_before_stale = state(0)->last_failure_ms;
    tunnelDownStreamPayload(clients[0], state(0)->control_line, stale);
    require(authenticationclientCanAuthenticate(clients[0]) && ! state(0)->auth_rejected,
            "stale rejection toggled availability");
    require(state(0)->last_failure == failure_before_stale && state(0)->last_failure_ms == failure_time_before_stale,
            "stale rejection rewrote status history");
    authTestPeerExpireSessions(server);
    discard authenticationclientSendPing(clients[0]);
    require(! state(0)->auth_rejected && authenticationclientCanAuthenticate(clients[0]),
            "session expiry acted like credential rejection");
    state(0)->continuity_error = true;
    require(! authenticationclientCanAuthenticate(clients[0]), "continuity error admitted cache");
    state(0)->continuity_error = false;
    authenticationclientTunnelOnQuiesceRequest(clients[0], wwLifecycleProcessShutdown());
    require(! authenticationclientCanAuthenticate(clients[0]), "stopping admitted cache");
    teardown();
}

static void testInvalidClockRefresh(void)
{
    setup(1);
    clock_fault = 1;
    start(0);
    require(! authenticationclientCanAuthenticate(clients[0]) && ! state(0)->users_loaded,
            "malformed first pull enabled cache");
    pump(1000);
    require(authenticationclientCanAuthenticate(clients[0]), "valid retry failed");
    user_t *user = usersLookupByIdentifier(state(0)->users, 42);
    discard userAccountTraffic(user, 4, 0, 0, NULL);
    for (unsigned fault = 1; fault <= 6; ++fault)
    {
        const uint64_t generation  = state(0)->users_generation;
        const uint64_t observation = user->client_time.first_report_ms;
        clock_fault                = fault;
        authenticationclientRequestPull(clients[0]);
        require(state(0)->users_generation == generation && local(0, false) == 4 &&
                    user->client_time.first_report_ms == observation && authenticationclientCanAuthenticate(clients[0]),
                "invalid clock replaced old cache/evidence");
        pump(1000);
        pump(1);
        pump(1);
        pump(1);
        user = usersLookupByIdentifier(state(0)->users, 42);
    }
    teardown();
}

static void testObservationMergeAndMetadataOnly(void)
{
    setup(1);
    start(0);
    start(1);
    traffic(0, 2);
    user_t        *a     = usersLookupByIdentifier(state(0)->users, 42);
    const uint64_t first = a->client_time.first_report_ms;
    atomicAddU64(&now_us, 20000);
    traffic(1, 3);
    user_t        *b     = usersLookupByIdentifier(state(1)->users, 42);
    const uint64_t later = b->client_time.first_report_ms;
    require(first < later, "distinct first observation fixture");
    authenticationclientRequestPush(clients[1]);
    require(authTestPeerFirstUse(server) == later, "later producer observation was not applied");
    authenticationclientRequestPush(clients[0]);
    require(authTestPeerFirstUse(server) == first && authTestPeerStats(server, 42).traffic.u == 5,
            "reverse arrival did not select earliest observation");
    authenticationclientRequestPull(clients[1]);
    a = usersLookupByIdentifier(state(0)->users, 42);
    b = usersLookupByIdentifier(state(1)->users, 42);
    require(a->timeinfo.first_usage_at_ms == first && b->timeinfo.first_usage_at_ms == first &&
                a->client_time.age_ms >= 40 && b->client_time.age_ms >= 40,
            "earliest canonical observation did not reach both clients with distinct server rate");
    atomicStoreU64(&server_wall_ms, 1);
    atomicStoreU64(&client_wall_ms, UINT64_C(900000000));
    const uint64_t old_age = a->client_time.age_ms;
    atomicAddU64(&now_us, 10000);
    authenticationclientRequestPull(clients[0]);
    a = usersLookupByIdentifier(state(0)->users, 42);
    require(a->client_time.age_ms >= old_age + 20 && a->client_time.first_report_ms == first,
            "wall correction rebased accounting clock or immutable observation");
    traffic(1, 1);
    authenticationclientRequestPush(clients[1]);
    require(authTestPeerFirstUse(server) == first, "later positive report moved canonical first use forward");
    teardown();

    setup(1);
    user_update_t saturated = {.mask = kUserUpdateStats, .stats.traffic.u = UINT64_MAX};
    authTestPeerSetUser(server, 42, &saturated);
    start(0);
    traffic(0, 1);
    authenticationclientRequestPush(clients[0]);
    require(authTestPeerSequence(server, 0) == 1 && authTestPeerFirstUse(server) != 0,
            "saturated counters dropped metadata-only observation");
    cJSON *batch = cJSON_Parse(captured_batch);
    cJSON *entry = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(batch, "users"), 0);
    require(jsonUnsigned(entry, "up") == 0 && jsonUnsigned(entry, "down") == 0,
            "metadata-only fixture had byte deltas");
    const uint64_t reported = jsonUnsigned(entry, "first-usage-at-ms");
    cJSON_Delete(batch);
    user_t *user = usersLookupByIdentifier(state(0)->users, 42);
    require(user->client_time.observation_acked && user->client_time.observed,
            "ACK erased origin or failed to settle metadata");
    const unsigned sent = pushes;
    authenticationclientRequestPush(clients[0]);
    pump(10);
    require(pushes == sent, "acknowledged metadata caused empty resend loop");
    user_handle_t handle = {.generation = state(0)->users_generation, .user_id = 42};
    require(authenticationclientUserAddTraffic(clients[0], &handle, 0, 1), "later download");
    authenticationclientRequestPush(clients[0]);
    batch = cJSON_Parse(captured_batch);
    entry = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(batch, "users"), 0);
    require(jsonUnsigned(entry, "first-usage-at-ms") == reported && authTestPeerSequence(server, 0) == 2,
            "later positive report changed producer observation");
    cJSON_Delete(batch);
    teardown();
}

static void testCatchupInterruptionAndCaptureRefusal(void)
{
    setup(1);
    start(0);
    require(authenticationclientRegisterApi(clients[0]), "capture-refusal status registration failed");
    disconnect(0);
    traffic(0, 1);
    pump(10);
    hold_push = true;
    pump(1);
    require(held_request != NULL && state(0)->pending_batch != NULL, "reconnect batch not retained");
    const uint64_t observation = usersLookupByIdentifier(state(0)->users, 42)->client_time.first_report_ms;
    traffic(0, 3);
    drop_ack = 1;
    deliverHeldRequest();
    require(state(0)->pending_batch != NULL && authTestPeerStats(server, 42).traffic.u == 1,
            "interrupted catch-up lost immutable batch");
    refuse_snapshot = true;
    pump(10); /* exact replay; required refresh follows on its own progress turn */
    pump(1);  /* refresh attempts capture, which refuses */
    require(! refuse_snapshot && state(0)->catchup_capture_needed && state(0)->progress_timer != NULL &&
                local(0, false) == 4 && local(0, true) == 1,
            "capture refusal lost evidence or independent retry");
    requireSyncPhase("capture_pending");
    pump(1);
    pump(1);
    require(authTestPeerStats(server, 42).traffic.u == 4 && authTestPeerSequence(server, 0) == 2 &&
                state(0)->pending_batch == NULL &&
                usersLookupByIdentifier(state(0)->users, 42)->client_time.first_report_ms == observation,
            "interrupted catch-up did not automatically settle exactly once");
    requireSyncPhase("idle");
    teardown();
}

static void testResumeTokenFailurePreservesAccounting(void)
{
    testCaseSet("resume token failure preserves cached authentication");
    setup(1);
    start(0);
    disconnect(0);
    discard userAccountTraffic(usersLookupByIdentifier(state(0)->users, 42), 5, 7, 0, NULL);
    pump(10);
    hold_push = true;
    pump(1);
    authenticationclient_tstate_t *ts = state(0);
    require(held_request != NULL && ts->pending_batch != NULL && ts->pending_entries_count == 1 &&
                ts->catchup_entries_count == 1,
            "token failure fixture did not retain a catch-up batch");
    drop_ack = 1;
    deliverHeldRequest();
    require(ts->control_line == NULL && ts->pending_batch != NULL && authTestPeerSequence(server, 0) == 1,
            "token failure fixture did not lose an accepted batch ACK");

    char                                    *pending = ts->pending_batch, *expected = stringDuplicate(pending);
    const uint32_t                           pending_length = ts->pending_batch_length;
    authenticationclient_accounting_entry_t *entries = ts->pending_entries, *debt = ts->catchup_entries;
    uint8_t expected_entries[sizeof(*entries)], expected_debt[sizeof(*debt)], checkpoint[SHA256_DIGEST_SIZE];
    memoryCopy(expected_entries, entries, sizeof(expected_entries));
    memoryCopy(expected_debt, debt, sizeof(expected_debt));
    memoryCopy(checkpoint, ts->last_ack_digest, sizeof(checkpoint));
    const uint64_t sequence = ts->next_batch_sequence, last_ack = ts->last_ack_sequence;
    char           epoch[65];
    memoryCopy(epoch, ts->accounting_epoch, sizeof(epoch));
    uint8_t old_token[64], current_token[64];
    char    old_epoch[65], current_epoch[65];
    authTestPeerCredentials(server, 0, old_token, old_epoch);
    char                      *before = authTestPeerSnapshot(server);
    user_accounting_snapshot_t before_user, after_user;
    userGetAccountingSnapshot(usersLookupByIdentifier(ts->users, 42), &before_user);

    fail_server_rng_call = 1;
    retryConnection(0);
    require(fail_server_rng_call == 0 && server_rng_calls == 1,
            "resume token RNG fault did not run at its intended position");
    require(last_response == kAuthenticationClientResponseTypeError &&
                ts->last_failure == kAuthenticationClientFailureRemoteError && ! ts->auth_rejected &&
                ! ts->continuity_error && authenticationclientCanAuthenticate(clients[0]),
            "token creation failure rejected usable cached credentials");
    require(ts->pending_batch == pending && ts->pending_batch_length == pending_length &&
                memoryEqual(pending, expected, pending_length) && ts->pending_entries == entries &&
                ts->pending_entries_count == 1 && memoryEqual(entries, expected_entries, sizeof(expected_entries)) &&
                ts->catchup_entries == debt && ts->catchup_entries_count == 1 &&
                memoryEqual(debt, expected_debt, sizeof(expected_debt)) && ts->orphan_debt_count == 0 &&
                local(0, true) == 0 && local(0, false) == 5,
            "token creation failure changed immutable usage, baseline or retained debt");
    userGetAccountingSnapshot(usersLookupByIdentifier(ts->users, 42), &after_user);
    require(ts->next_batch_sequence == sequence && ts->last_ack_sequence == last_ack &&
                memoryEqual(ts->last_ack_digest, checkpoint, sizeof(checkpoint)) &&
                memoryEqual(ts->accounting_epoch, epoch, sizeof(epoch)) && after_user.observation_pending &&
                after_user.first_usage_at_ms == before_user.first_usage_at_ms &&
                after_user.first_local_at_ms == before_user.first_local_at_ms,
            "token creation failure changed client checkpoint or first-use evidence");
    char *after = authTestPeerSnapshot(server);
    authTestPeerCredentials(server, 0, current_token, current_epoch);
    require(strcmp(before, after) == 0 && memoryEqual(old_token, current_token, sizeof(old_token)) &&
                strcmp(old_epoch, current_epoch) == 0,
            "token creation failure changed the old server session or checkpoint");
    user_handle_t handle;
    user_ip_key_t ip = {.type = 4, .bytes = {192, 0, 2, 1}};
    require(authenticationclientGetUserByPassword(clients[0], "account-0", &handle) &&
                authenticationclientUserTryAdmitConnection(
                    clients[0], &handle, &ip, authenticationclientLocalTimeMS()) == kUserAdmissionOk,
            "token creation failure disabled cached lookup or admission");
    authenticationclientUserReleaseConnection(clients[0], &handle, &ip);
    const uint64_t now = authenticationclientLocalTimeMS(), due = ts->reconnect_due_ms;
    require(ts->control_line == NULL && ts->reconnect_timer != NULL && due >= now + 1000 && due <= now + 75000 &&
                ts->sync_retry_not_before_ms <= due,
            "token creation failure did not schedule bounded reconnect backoff");
    pump((unsigned) (due - now - 1));
    require(ts->control_line == NULL && pushes == 1 && server_rng_calls == 1,
            "token creation failure retried before its deadline");
    retryConnection(0);
    pump(1);
    pump(1);
    require(ts->pending_batch == NULL && ts->pending_entries_count == 0 && ts->catchup_entries_count == 0 &&
                ts->last_ack_sequence == sequence && ts->next_batch_sequence == sequence + 1 && local(0, true) == 5 &&
                pushes == 2 && authTestPeerSequence(server, 0) == 1 && authTestPeerStats(server, 42).traffic.u == 5 &&
                authTestPeerStats(server, 42).traffic.d == 7 && authenticationclientIsReady(clients[0]),
            "retry after token creation failure lost usage or charged exact replay twice");
    memoryFree(expected);
    cJSON_free(before);
    cJSON_free(after);
    teardown();
}

static void testFreshEpochFailurePreservesSession(void)
{
    testCaseSet("fresh epoch failure preserves prior session and checkpoint");
    setup(1);
    start(0);
    traffic(0, 10);
    authenticationclientRequestPush(clients[0]);
    require(authTestPeerSequence(server, 0) == 1, "epoch failure fixture has no accepted checkpoint");
    uint8_t token[64], current_token[64];
    char    epoch[65], current_epoch[65];
    authTestPeerCredentials(server, 0, token, epoch);
    char   *before = authTestPeerSnapshot(server);
    line_t *line   = lineCreate(chain->line_pools, 0);
    tunnelUpStreamInit(server, line);
    static const char enroll[]        = "{\"name\":\"edge-a\",\"secret\":\"secret\"}";
    const uint8_t     empty_token[64] = {0};
    raw_response[0]                   = -1;
    fail_server_rng_call              = 2;
    rawRequest(line, empty_token, kAuthenticationClientRequestTypeAuthenticate, enroll, sizeof(enroll) - 1);
    require(fail_server_rng_call == 0 && server_rng_calls == 2,
            "fresh epoch RNG fault did not run at its intended position");
    require(raw_response[0] == kAuthenticationClientResponseTypeError &&
                strcmp(raw_body[0], "session-unavailable") == 0,
            "epoch creation failure was misclassified as invalid credentials");
    char *after = authTestPeerSnapshot(server);
    authTestPeerCredentials(server, 0, current_token, current_epoch);
    require(strcmp(before, after) == 0 && memoryEqual(token, current_token, sizeof(token)) &&
                strcmp(epoch, current_epoch) == 0 && authTestPeerSequence(server, 0) == 1,
            "epoch creation failure replaced a session, epoch or accounting checkpoint");
    cJSON_free(before);
    cJSON_free(after);
    tunnelUpStreamFin(server, line);
    lineDestroy(line);
    teardown();
    testCaseSet("authentication sync loss and continuity");
}

static void testMalformedUsageAcksPreserveAccounting(void)
{
    static const char *const cases[] = {
        "usage ACK trailing input",
        "usage ACK duplicate field",
        "usage ACK decoded NUL epoch",
        "usage ACK decoded NUL digest",
        "usage ACK invalid UTF-8",
    };
    for (unsigned fault = 1; fault <= sizeof(cases) / sizeof(cases[0]); ++fault)
    {
        testCaseSet(cases[fault - 1]);
        setup(1);
        start(0);
        disconnect(0);
        discard userAccountTraffic(usersLookupByIdentifier(state(0)->users, 42), 5, 7, 0, NULL);
        pump(10);
        hold_push = true;
        pump(1);
        authenticationclient_tstate_t *ts = state(0);
        require(held_request != NULL && ts->pending_batch != NULL && ts->pending_entries_count == 1 &&
                    ts->catchup_entries_count == 1,
                "malformed ACK fixture did not retain a catch-up batch");
        char                                    *pending        = ts->pending_batch;
        const uint32_t                           pending_length = ts->pending_batch_length;
        char                                    *expected       = stringDuplicate(pending);
        authenticationclient_accounting_entry_t *entries = ts->pending_entries, *debt = ts->catchup_entries;
        uint8_t expected_entries[sizeof(*entries)], expected_debt[sizeof(*debt)], checkpoint[32];
        memoryCopy(expected_entries, entries, sizeof(expected_entries));
        memoryCopy(expected_debt, debt, sizeof(expected_debt));
        memoryCopy(checkpoint, ts->last_ack_digest, sizeof(checkpoint));
        const uint64_t             sequence = ts->next_batch_sequence, last_ack = ts->last_ack_sequence;
        user_accounting_snapshot_t before, after;
        userGetAccountingSnapshot(usersLookupByIdentifier(ts->users, 42), &before);
        require(before.observation_pending && local(0, true) == 0, "malformed ACK observation fixture");
        ack_fault = fault;
        deliverHeldRequest();
        userGetAccountingSnapshot(usersLookupByIdentifier(ts->users, 42), &after);
        require(ack_fault == 0 && ts->last_failure == kAuthenticationClientFailureInvalidResponse &&
                    ts->pending_batch == pending && ts->pending_batch_length == pending_length &&
                    memoryEqual(ts->pending_batch, expected, pending_length),
                "malformed ACK consumed or changed the immutable retry payload");
        require(ts->pending_entries == entries && ts->pending_entries_count == 1 &&
                    memoryEqual(entries, expected_entries, sizeof(expected_entries)) && ts->catchup_entries == debt &&
                    ts->catchup_entries_count == 1 && memoryEqual(debt, expected_debt, sizeof(expected_debt)) &&
                    ts->orphan_debt_count == 0 && local(0, true) == 0 && local(0, false) == 5,
                "malformed ACK consumed accounting entries, baseline or debt");
        require(ts->next_batch_sequence == sequence && ts->last_ack_sequence == last_ack &&
                    memoryEqual(ts->last_ack_digest, checkpoint, sizeof(checkpoint)) && after.observation_pending &&
                    after.first_usage_at_ms == before.first_usage_at_ms &&
                    after.first_local_at_ms == before.first_local_at_ms,
                "malformed ACK advanced the checkpoint or settled first-use evidence");
        require(authTestPeerStats(server, 42).traffic.u == 5 && authTestPeerStats(server, 42).traffic.d == 7,
                "malformed ACK fixture did not commit the server batch");
        retryConnection(0);
        pump(1);
        pump(1);
        userGetAccountingSnapshot(usersLookupByIdentifier(ts->users, 42), &after);
        require(ts->pending_batch == NULL && ts->pending_entries_count == 0 && ts->catchup_entries_count == 0 &&
                    ts->last_ack_sequence == sequence && ts->next_batch_sequence == sequence + 1 &&
                    local(0, true) == 5 && ! after.observation_pending && pushes == 2 &&
                    authTestPeerStats(server, 42).traffic.u == 5 && authTestPeerStats(server, 42).traffic.d == 7,
                "valid replay failed to settle exactly once after malformed ACK");
        memoryFree(expected);
        teardown();
    }
    testCaseSet("authentication sync loss and continuity");
}

static void testCatchupSurvivesSaturatedRebase(void)
{
    setup(1);
    start(0);
    disconnect(0);
    discard userAccountTraffic(usersLookupByIdentifier(state(0)->users, 42), 5, 7, 0, NULL);
    pump(10);
    require(state(0)->catchup_entries_count == 1, "saturation capture fixture");
    line_t *other = lineCreate(chain->line_pools, 0);
    tunnelUpStreamInit(server, other);
    uint8_t    token[64] = {0};
    const char enroll[]  = "{\"name\":\"edge-b\",\"secret\":\"secret\"}";
    rawRequest(other, token, kAuthenticationClientRequestTypeAuthenticate, enroll, sizeof(enroll) - 1);
    char epoch[65], text[256];
    authTestPeerCredentials(server, 1, token, epoch);
    snprintf(text,
             sizeof(text),
             "{\"epoch\":\"%s\",\"sequence\":1,\"users\":[{\"id\":42,\"up\":\"18446744073709551615\","
             "\"down\":\"18446744073709551615\","
             "\"first-usage-at-ms\":1}]}",
             epoch);
    rawBatch(other, token, text);
    require(raw_response[0] == 0, "saturating other producer report");
    tunnelUpStreamFin(server, other);
    lineDestroy(other);
    /* A normal pull between capture and its scheduled batch rebases both
     * visible counters to MAX; the captured relative debt must still settle. */
    authenticationclientRequestPull(clients[0]);
    require(local(0, false) == UINT64_MAX && local(0, true) == UINT64_MAX, "saturated rebase fixture");
    disconnect(0);
    hold_pull = true;
    pump(10);
    require(held_request != NULL, "saturated reconnect refresh was not held");
    deliverHeldRequest();
    require(state(0)->catchup_entries_count == 1 && state(0)->catchup_entries[0].delta.u == 5 &&
                state(0)->catchup_entries[0].delta.d == 7,
            "reconnect discarded captured traffic hidden by saturated counters");
    disconnect(0);
    hold_pull = true;
    pump(10);
    require(held_request != NULL, "repeated reconnect refresh was not held");
    refuse_snapshot = true;
    deliverHeldRequest();
    require(! refuse_snapshot && state(0)->catchup_capture_needed && state(0)->catchup_entries_count == 1 &&
                state(0)->catchup_entries[0].delta.u == 5 && state(0)->catchup_entries[0].delta.d == 7,
            "refused reconnect capture discarded retained traffic");
    drop_ack = 1;
    pump(1);
    require(state(0)->pending_batch != NULL && authTestPeerSequence(server, 0) == 1,
            "saturated catch-up lost the batch after its ACK was dropped");
    pump(10);
    pump(1);
    pump(1);
    require(state(0)->catchup_entries_count == 0 && state(0)->pending_batch == NULL,
            "saturated aggregate hid captured debt and wedged catch-up");
    cJSON       *batch = cJSON_Parse(captured_batch);
    const cJSON *entry = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(batch, "users"), 0);
    require(jsonUnsigned(entry, "up") == 5 && jsonUnsigned(entry, "down") == 7 &&
                authTestPeerSequence(server, 0) == 1 && pushes == 2,
            "captured saturated debt was not reported exactly once");
    cJSON_Delete(batch);
    const unsigned sent = pushes;
    pump(10);
    require(pushes == sent && state(0)->progress_timer == NULL, "saturated catch-up retained an empty retry loop");
    teardown();
}

static void testCatchupRecaptureMergesOverlappingTraffic(void)
{
    setup(1);
    start(0);
    disconnect(0);
    discard userAccountTraffic(usersLookupByIdentifier(state(0)->users, 42), 5, 7, 0, NULL);
    pump(10);
    require(state(0)->catchup_entries_count == 1, "overlapping capture fixture");
    disconnect(0);
    discard userAccountTraffic(usersLookupByIdentifier(state(0)->users, 42), 3, 4, 0, NULL);
    hold_pull = true;
    pump(10);
    require(held_request != NULL, "overlapping reconnect refresh was not held");
    deliverHeldRequest();
    hold_push = true;
    pump(1);
    require(held_request != NULL && state(0)->pending_entries_count == 1,
            "recaptured usage did not create a bounded batch");
    cJSON       *batch = cJSON_Parse(captured_batch);
    const cJSON *entry = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(batch, "users"), 0);
    require(jsonUnsigned(entry, "up") == 8 && jsonUnsigned(entry, "down") == 11,
            "recapture duplicated old debt or omitted newer offline traffic");
    cJSON_Delete(batch);
    discard userAccountTraffic(usersLookupByIdentifier(state(0)->users, 42), 2, 3, 0, NULL);
    drop_ack = 1;
    deliverHeldRequest();
    require(state(0)->pending_batch != NULL && authTestPeerStats(server, 42).traffic.u == 8 &&
                authTestPeerStats(server, 42).traffic.d == 11,
            "lost ACK did not retain the immutable recaptured batch");
    pump(10); /* Replay the same batch before capturing traffic produced after it. */
    pump(1);
    pump(1);
    pump(1);
    require(authTestPeerStats(server, 42).traffic.u == 10 && authTestPeerStats(server, 42).traffic.d == 14 &&
                authTestPeerSequence(server, 0) == 2 && state(0)->pending_batch == NULL &&
                state(0)->catchup_entries_count == 0 && pushes == 3,
            "recaptured debt or traffic after the batch was lost or reported twice");
    const unsigned sent = pushes;
    pump(10);
    require(pushes == sent && state(0)->progress_timer == NULL, "recaptured debt retained an empty retry loop");
    teardown();
}

static void testOfflineLocalQuotas(void)
{
    setup(1);
    user_update_t initial = {.mask                = kUserUpdateStats | kUserUpdateLimit,
                             .stats.traffic.u     = 80,
                             .limit.traffic.total = 100,
                             .limit.cons_out      = 1,
                             .limit.ips           = 1};
    authTestPeerSetUser(server, 42, &initial);
    start(0);
    start(1);
    disconnect(0);
    disconnect(1);
    for (unsigned i = 0; i < 2; ++i)
    {
        user_handle_t handle;
        require(authenticationclientGetUserByPassword(clients[i], "account-0", &handle),
                "offline credential eligibility");
        user_ip_key_t ip = {.type = 4, .bytes = {192, 0, 2, 1}};
        require(authenticationclientUserTryAdmitConnection(clients[i], &handle, &ip, 100000) == kUserAdmissionOk &&
                    authenticationclientUserTryAdmitConnection(clients[i], &handle, &ip, 100000) ==
                        kUserAdmissionConnectionLimited,
                "offline local reservation limits failed");
        require(authenticationclientUserAccountTraffic(clients[i], &handle, 20, 0, 100000),
                "offline bytes did not consume quota");
        authenticationclientUserReleaseConnection(clients[i], &handle, &ip);
        require(! authenticationclientGetUserByPassword(clients[i], "account-0", &handle),
                "offline over-quota login admitted");
    }
    user_update_t disabled = {
        .mask = kUserUpdateEnabled | kUserUpdateLimit, .enabled = false, .limit.traffic.total = 90};
    authTestPeerSetUser(server, 42, &disabled);
    pump(10);
    for (unsigned i = 0; i < 5; ++i)
        pump(1);
    require(authTestPeerStats(server, 42).traffic.u == 120,
            "local availability overshoot was discarded or double counted");
    require(! userIsEnabled(usersLookupByIdentifier(state(0)->users, 42)) &&
                ! userIsEnabled(usersLookupByIdentifier(state(1)->users, 42)),
            "reconnect did not install changed policy");
    teardown();
}

typedef struct refresh_traffic_context_s
{
    user_handle_t handle;
    atomic_bool   started, stop, finished;
    atomic_uint   produced;
} refresh_traffic_context_t;

static void *trafficDuringRefresh(void *argument)
{
    refresh_traffic_context_t *context = argument;
    atomic_store(&context->started, true);
    for (unsigned i = 0; i < 1000000 && ! atomic_load(&context->stop); ++i)
    {
        require(! authenticationclientUserAccountTraffic(clients[0], &context->handle, 1, 0, 0),
                "concurrent traffic closed");
        atomic_fetch_add(&context->produced, 1);
    }
    atomic_store(&context->finished, true);
    return NULL;
}

static void sampleTrafficDuringRefresh(refresh_traffic_context_t *context)
{
    const unsigned                 before         = atomic_load(&context->produced);
    authenticationclient_tstate_t *ts             = state(0);
    const uint64_t                 sequence       = ts->next_batch_sequence;
    const bool                     pull_in_flight = ts->pull_in_flight, pull_required = ts->pull_required;
    const bool push_requested = ts->push_requested, observation_requested = ts->first_usage_push_requested;
    authenticationclient_status_t sample;
    authenticationclientStatusSnapshot(
        clients[0], true, 1024 * 1024, authenticationclientLocalTimeMS() + 1000, &sample);
    const unsigned after = atomic_load(&context->produced);
    require(! atomic_load(&context->finished), "traffic exhausted its finite limit before concurrent status sample");
    /* A traffic counter commit precedes its produced notification, so one
     * currently committing byte may be absent from the upper notification. */
    require(sample.accounting_state == kAuthenticationClientAccountingAvailable && sample.can_authenticate &&
                sample.locally_unacknowledged_upload_bytes >= before &&
                sample.locally_unacknowledged_upload_bytes <= (uint64_t) after + 1 &&
                sample.locally_unacknowledged_download_bytes == 0 && ! sample.accounting_lower_bound &&
                sample.first_use_observation_count == 0 && sample.usage_user_count <= 1 &&
                sample.sampling_started_ms <= sample.sampling_finished_ms,
            "concurrent status debt escaped sampling bounds or observation state");
    require(ts->next_batch_sequence == sequence && ts->pending_batch == NULL && ts->pending_entries_count == 0 &&
                ts->pull_in_flight == pull_in_flight && ts->pull_required == pull_required &&
                ts->push_requested == push_requested && ts->first_usage_push_requested == observation_requested &&
                local(0, true) == 1,
            "concurrent status changed baseline, batch, observation or synchronization state");
}

static void testTrafficDuringRefresh(void)
{
    setup(1);
    start(0);
    traffic(0, 1);
    authenticationclientRequestPush(clients[0]);
    user_t        *user   = usersLookupByIdentifier(state(0)->users, 42);
    const uint64_t origin = user->client_time.first_report_ms;
    user_handle_t  handle = {.generation = state(0)->users_generation, .user_id = 42};
    require(authenticationclientUserTryAdmitConnection(clients[0], &handle, NULL, 100000) == kUserAdmissionOk,
            "concurrent reservation");
    refresh_traffic_context_t context = {.handle = handle};
    atomic_init(&context.started, false);
    atomic_init(&context.stop, false);
    atomic_init(&context.finished, false);
    atomic_init(&context.produced, 0);
    hold_pull = true;
    authenticationclientRequestPull(clients[0]);
    pthread_t thread;
    require(pthread_create(&thread, NULL, trafficDuringRefresh, &context) == 0, "refresh traffic thread");
    for (unsigned attempts = 0; attempts < 1000 && atomic_load(&context.produced) == 0; ++attempts)
        wwSleepMS(1);
    require(atomic_load(&context.started) && atomic_load(&context.produced) != 0,
            "refresh producer failed to start within its bounded wait");
    sampleTrafficDuringRefresh(&context);
    deliverHeldRequest();
    sampleTrafficDuringRefresh(&context);
    for (unsigned i = 0; i < 4; ++i)
        authenticationclientRequestPull(clients[0]);
    atomic_store(&context.stop, true);
    pthread_join(thread, NULL);
    const uint64_t total = 1 + (uint64_t) atomic_load(&context.produced);
    require(local(0, false) == total && local(0, true) == 1, "refresh/status lost concurrently produced deltas");
    user = usersLookupByIdentifier(state(0)->users, 42);
    require(user->client_time.first_report_ms == origin && user->client_time.observation_acked &&
                user->runtime.active_cons_out == 1,
            "refresh lost observation/ACK state or reservation during traffic");
    authenticationclientUserReleaseConnection(clients[0], &handle, NULL);
    authenticationclientRequestPush(clients[0]);
    require(authTestPeerStats(server, 42).traffic.u == total, "concurrent refresh/status/report reconciliation");
    teardown();
}

static void testSharedBandwidthReservations(void)
{
    setup(1);
    start(0);
    disconnect(0);
    user_handle_t handle;
    userHandleSet(&handle, state(0)->users_generation, 42);
    uint64_t first  = authenticationclientUserBandwidthRegister(clients[0], &handle, kUserBandwidthUpload);
    uint64_t second = authenticationclientUserBandwidthRegister(clients[0], &handle, kUserBandwidthDownload);
    require(first != 0 && second > first, "client tickets not unique");
    buffer_budget_cost_t cost = {3U << 20, 3U << 20, 100};
    require(authenticationclientUserBandwidthReserve(clients[0], &handle, first, cost), "shared user reservation");
    require(! authenticationclientUserBandwidthReserve(
                clients[0], &handle, second, (buffer_budget_cost_t) {2U << 20, 2U << 20, 1}),
            "shared user byte limit bypassed");
    require(! authenticationclientUserBandwidthReserve(clients[0], &handle, second, (buffer_budget_cost_t) {0, 0, 925}),
            "shared user empty-entry limit bypassed");
    require(state(0)->bandwidth_queued_cost.bytes == cost.bytes &&
                state(0)->bandwidth_queued_cost.entries == cost.entries,
            "refused reservation changed client totals");
    users_t *replacement = memoryAllocateAligned(sizeof(*replacement), 32);
    require(usersCreate(replacement), "replacement users");
    user_t source;
    require(userCreate(&source, "recreated-bandwidth"), "recreated user");
    userSetId(&source, 42);
    require(usersAddUser(replacement, &source), "replacement insertion");
    userDestroy(&source);
    rwlockWriteLock(&state(0)->users_lock);
    users_t *old    = state(0)->users;
    state(0)->users = replacement;
    ++state(0)->users_generation;
    rwlockWriteUnlock(&state(0)->users_lock);
    usersDestroy(old);
    memoryFreeAligned(old);
    require(
        authenticationclientUserBandwidthPreview(clients[0], &handle, kUserBandwidthUpload, first, 1, false).decision ==
            kUserDeliveryReject,
        "recreated user accepted stale waiter");
    uint64_t recreated = authenticationclientUserBandwidthRegister(clients[0], &handle, kUserBandwidthUpload);
    require(recreated > second, "recreated account reused ticket");
    require(
        authenticationclientUserBandwidthReserve(clients[0], &handle, recreated, (buffer_budget_cost_t) {10, 100, 1}),
        "recreated account reservation");
    authenticationclientUserBandwidthRelease(clients[0], &handle, first, cost);
    require(usersLookupByIdentifier(replacement, 42)->runtime.queued_cost.bytes == 10 &&
                state(0)->bandwidth_queued_cost.bytes == 10,
            "old release debited recreated account");
    authenticationclientUserBandwidthCancel(clients[0], &handle, kUserBandwidthUpload, first);
    authenticationclientUserBandwidthCancel(clients[0], &handle, kUserBandwidthDownload, second);
    authenticationclientUserBandwidthCancel(clients[0], &handle, kUserBandwidthUpload, recreated);
    require(state(0)->bandwidth_ticket_count == 0 && state(0)->bandwidth_queued_cost.bytes == 0,
            "ticket cancellation leaked aggregate costs");
    state(0)->bandwidth_last_ticket = UINT64_MAX;
    require(authenticationclientUserBandwidthRegister(clients[0], &handle, kUserBandwidthUpload) == 0,
            "ticket exhaustion wrapped");
    teardown();
}

void authTestControllerUpdateUser(tunnel_t *auth, const user_update_t *update)
{
    authenticationclient_tstate_t *ts = tunnelGetState(auth);
    rwlockReadLock(&ts->users_lock);
    user_t *user = usersLookupByIdentifier(ts->users, 42);
    require(user != NULL && usersUpdateUser(ts->users, user, update), "controller cached-user update");
    rwlockReadUnlock(&ts->users_lock);
}

#if defined(AUTHENTICATION_SYNC_HAVE_CONTROLLER)
static void testControllerBandwidth(void)
{
    setup(1);
    start(0);
    disconnect(0);
    authTestControllerBandwidthCases(clients[0], chain, pump);
    teardown();
    const uint32_t multipliers[] = {500, 2000};
    for (size_t i = 0; i < sizeof(multipliers) / sizeof(multipliers[0]); ++i)
    {
        setup(1);
        startWithMultiplier(0, multipliers[i]);
        disconnect(0);
        authTestControllerMultiplierCases(clients[0], chain, pump, multipliers[i]);
        teardown();
    }
}

static void testOfflineControllerExpiry(void)
{
    for (unsigned idle = 0; idle < 3; ++idle)
    {
        setup(1);
        user_update_t update = {.mask                                 = kUserUpdateTimeInfo | kUserUpdateLimit,
                                .timeinfo.expire_after_first_usage_ms = 100,
                                .limit.bandwidth.u                    = idle == 2 ? 1 : 0};
        authTestPeerSetUser(server, 42, &update);
        start(0);
        tunnel_t *controller = authTestControllerCreate(clients[0]);
        line_t   *line       = authTestControllerOpen(controller, chain);
        require(lineIsAlive(line), "controller did not admit loaded account");
        disconnect(0);
        if (idle == 2)
            tunnelDownStreamPause(controller, line);
        authTestControllerPayload(controller, line);
        require(lineIsAlive(line) && local(0, false) == (idle == 2 ? 0 : 1),
                "controller arrival queued/forwarding charge failed offline");
        atomicAddU64(&now_us, 101000);
        if (idle)
            authTestControllerSweep(controller);
        else
            authTestControllerPayload(controller, line);
        require(! lineIsAlive(line), "offline controller payload/sweep ignored local expiry");
        require(usersLookupByIdentifier(state(0)->users, 42)->runtime.active_cons_out == 0,
                "expiry failed to release reservation");
        lineUnref(line);
        user_handle_t handle;
        require(! authenticationclientGetUserByPassword(clients[0], "account-0", &handle),
                "expired offline login admitted");
        authTestControllerDestroy(controller);
        teardown();
    }
}

#endif

static void testOfflineFirstUseDeadline(void)
{
    setup(1);
    user_update_t update = {.mask = kUserUpdateTimeInfo, .timeinfo.expire_after_first_usage_ms = 100};
    authTestPeerSetUser(server, 42, &update);
    start(0);
    user_handle_t handle;
    userHandleSet(&handle, state(0)->users_generation, 42);
    disconnect(0);
    require(! authenticationclientUserAccountTraffic(clients[0], &handle, 1, 0, 100000), "first traffic closed early");
    atomicStoreU64(&now_us, 100101000);
    require(authenticationclientUserShouldClose(clients[0], &handle, 100101),
            "offline first-use countdown waited for server receipt");
    const uint64_t observation = usersLookupByIdentifier(state(0)->users, 42)->client_time.first_report_ms;
    pump(10);
    pump(1);
    pump(1);
    require(authTestPeerStats(server, 42).traffic.u == 1 &&
                authenticationclientUserShouldClose(clients[0], &handle, authenticationclientLocalTimeMS()) &&
                usersLookupByIdentifier(state(0)->users, 42)->client_time.first_report_ms == observation,
            "delayed reconnect/ACK restarted first-use expiry");
    teardown();
}

static cJSON *statusBody(const char *body, size_t allowance, enum api_result_e expected)
{
    const node_api_operation_t *operation = nodeApiFind(clients[0], "status");
    require(operation != NULL && operation->read_only && operation->execution == kNodeApiSpecifiedWorker &&
                operation->wid == 0,
            "status descriptor contract");
    sbuf_t *request = bufferpoolGetBestFit(pools[0], (uint32_t) strlen(body), 0);
    sbufSetLength(request, (uint32_t) strlen(body));
    memoryCopy(sbufGetMutablePtr(request), body, strlen(body));
    node_api_call_context_t context = {.operation                = "status",
                                       .principal                = "unit",
                                       .max_response_body_size   = 4096,
                                       .working_memory_allowance = allowance};
    api_result_t            result  = operation->handler(clients[0], request, &context);
    require(result.result_code == expected && result.buffer != NULL, "status result contract");
    cJSON *json = cJSON_ParseWithLength((const char *) sbufGetRawPtr(result.buffer), sbufGetLength(result.buffer));
    require(cJSON_IsObject(json), "status did not return JSON");
    bufferpoolReuseBuffer(pools[0], result.buffer);
    return json;
}

static void requireMultiplierSetting(cJSON *settings, uint32_t expected)
{
    static char name[] = "multiplier-config", next[] = "transport";
    node_t      node   = {.name = name, .next = next, .node_settings_json = settings};
    tunnel_t   *client = authenticationclientTunnelCreate(&node);
    if (expected == 0)
        require(client == NULL, "invalid traffic multiplier was accepted");
    else
    {
        require(client != NULL, "valid traffic multiplier was rejected");
        clients[0] = client;
        require(state(0)->traffic_multiplier == expected, "traffic multiplier was rounded or defaulted");
        cJSON       *status     = statusBody("{}", 1024 * 1024, kApiResultOk);
        const cJSON *multiplier = cJSON_GetObjectItemCaseSensitive(status, "traffic_multiplier");
        require(cJSON_IsNumber(multiplier) &&
                    multiplier->valuedouble == (double) expected / kUserTrafficMultiplierScale,
                "status did not expose the configured multiplier as a JSON number");
        cJSON_Delete(status);
        authenticationclientTunnelDestroy(client, wwLifecycleStartupRollback());
        clients[0] = NULL;
    }
    cJSON_Delete(settings);
}

static void testMultiplierSettings(void)
{
    static const struct
    {
        const char *json;
        uint32_t    expected;
    } cases[] = {
        {NULL, 1000},        {"1", 1000},       {"0.5", 500},    {"1.5", 1500}, {"2", 2000},
        {"0.001", 1},        {"1e-3", 1},       {"1.234", 1234}, {"0.29", 290}, {"0.999", 999},
        {"999.999", 999999}, {"1000", 1000000}, {"0", 0},        {"-1", 0},     {"\"0.5\"", 0},
        {"null", 0},         {"true", 0},       {"[]", 0},       {"{}", 0},     {"0.0001", 0},
        {"0.000001", 0},     {"1000.001", 0},   {"1.2345", 0},   {"1.0001", 0}, {"1,\"traffic-multiplier\":2", 0}};
    setup(1);
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        char text[256];
        if (cases[i].json == NULL)
            snprintf(text, sizeof(text), "{\"name\":\"edge-a\",\"secret\":\"secret\"}");
        else
            snprintf(text,
                     sizeof(text),
                     "{\"name\":\"edge-a\",\"secret\":\"secret\",\"traffic-multiplier\":%s}",
                     cases[i].json);
        cJSON *settings = cJSON_Parse(text);
        require(settings != NULL, "traffic multiplier config fixture did not parse");
        requireMultiplierSetting(settings, cases[i].expected);
    }
    const double nonfinite[] = {NAN, INFINITY, -INFINITY};
    for (unsigned i = 0; i < sizeof(nonfinite) / sizeof(nonfinite[0]); ++i)
    {
        cJSON  *settings = cJSON_Parse("{\"name\":\"edge-a\",\"secret\":\"secret\"}");
        discard cJSON_AddNumberToObject(settings, "traffic-multiplier", nonfinite[i]);
        requireMultiplierSetting(settings, 0);
    }
    teardown();
}

static void testSyncLimitSettings(void)
{
    setup(1);
    const char *const keys[]    = {"sync-max-users", "sync-max-bytes"};
    const char *const invalid[] = {
        "0", "-1", "1.0", "1e0", "\"1\"", "null", "true", "[]", "{}", "18446744073709551616"};
    for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); ++k)
    {
        for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        {
            char text[256];
            snprintf(text, sizeof(text), "{\"name\":\"edge-a\",\"secret\":\"secret\",\"%s\":%s}", keys[k], invalid[i]);
            cJSON *settings = cJSON_Parse(text);
            require(settings != NULL, "sync-limit config fixture parse");
            requireMultiplierSetting(settings, 0);
        }
        char duplicate[256];
        snprintf(duplicate,
                 sizeof(duplicate),
                 "{\"name\":\"edge-a\",\"secret\":\"secret\",\"%s\":1,\"%s\":2}",
                 keys[k],
                 keys[k]);
        requireMultiplierSetting(cJSON_Parse(duplicate), 0);
    }
    static char node_name[] = "sync-limits", next[] = "transport";
    cJSON      *settings =
        cJSON_Parse("{\"name\":\"edge-a\",\"secret\":\"secret\",\"sync-max-users\":1,\"sync-max-bytes\":1}");
    node_t    node   = {.name = node_name, .next = next, .node_settings_json = settings};
    tunnel_t *client = authenticationclientTunnelCreate(&node);
    require(client != NULL, "minimum sync-limit settings refused");
    authenticationclient_tstate_t *ts = tunnelGetState(client);
    require(ts->sync_max_users == 1 && ts->sync_max_bytes == 1, "sync limits were rounded/defaulted");
    authenticationclientTunnelDestroy(client, wwLifecycleStartupRollback());
    cJSON_Delete(settings);
    teardown();
}

static void testCredentialSettingsLimit(void)
{
    setup(1);
    const unsigned char symbols[] = {'a', '\\', '\1'};
    const size_t        costs[]   = {1, 2, 6};
    for (unsigned i = 0; i < sizeof(symbols); ++i)
    {
        cJSON  *handshake = cJSON_CreateObject();
        discard cJSON_AddStringToObject(handshake, "name", "edge-a");
        discard cJSON_AddStringToObject(handshake, "secret", "");
        discard cJSON_AddStringToObject(
            handshake, "epoch", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        char        *text      = cJSON_PrintUnformatted(handshake);
        const size_t available = 16375U - strlen(text); /* 16 KiB payload minus frame header. */
        cJSON_free(text);
        char        *secret   = memoryAllocate(available + 2);
        const size_t repeated = available / costs[i], tail = available % costs[i];
        memorySet(secret, symbols[i], repeated);
        memorySet(secret + repeated, 'a', tail);
        const size_t length = repeated + tail;
        secret[length]      = 0;
        cJSON_ReplaceItemInObjectCaseSensitive(handshake, "secret", cJSON_CreateString(secret));
        text = cJSON_PrintUnformatted(handshake);
        require(strlen(text) == 16375U, "credential boundary did not measure actual worst handshake");
        cJSON_free(text);
        cJSON_Delete(handshake);
        cJSON  *settings = cJSON_CreateObject();
        discard cJSON_AddStringToObject(settings, "name", "edge-a");
        discard cJSON_AddStringToObject(settings, "secret", secret);
        requireMultiplierSetting(settings, 1000);
        secret[length]     = 'a';
        secret[length + 1] = 0;
        settings           = cJSON_CreateObject();
        discard cJSON_AddStringToObject(settings, "name", "edge-a");
        discard cJSON_AddStringToObject(settings, "secret", secret);
        requireMultiplierSetting(settings, 0);
        memoryFree(secret);
    }
    teardown();
}

static user_stat_t localStats(unsigned i, uint64_t id)
{
    user_stat_t stats;
    userGetStats(usersLookupByIdentifier(state(i)->users, id), &stats);
    return stats;
}

static void testMultiplierFragmentAccounting(void)
{
    const uint32_t multipliers[] = {500, 1000, 1500, 2000};
    for (unsigned i = 0; i < sizeof(multipliers) / sizeof(multipliers[0]); ++i)
    {
        setup(2);
        startWithMultiplier(0, multipliers[i]);
        disconnect(0);
        user_handle_t first  = {.generation = state(0)->users_generation, .user_id = 42};
        user_handle_t second = {.generation = state(0)->users_generation, .user_id = 43};
        require(authenticationclientUserAddTraffic(clients[0], &second, 1, 1), "second account fractional traffic");
        for (unsigned fragment = 0; fragment < 9; ++fragment)
        {
            require(authenticationclientUserAddTraffic(clients[0], &first, 1, 0), "fragmented upload");
            if (fragment < 7)
                require(! authenticationclientUserAccountTraffic(clients[0], &first, 0, 1, 100000),
                        "fragmented download unexpectedly closed account");
        }
        const user_stat_t a = localStats(0, 42), b = localStats(0, 43);
        require(a.traffic.u == (uint64_t) 9 * multipliers[i] / kUserTrafficMultiplierScale &&
                    a.traffic.d == (uint64_t) 7 * multipliers[i] / kUserTrafficMultiplierScale &&
                    b.traffic.u == multipliers[i] / kUserTrafficMultiplierScale &&
                    b.traffic.d == multipliers[i] / kUserTrafficMultiplierScale,
                "fragmentation or another user/direction changed charged traffic");
        teardown();
    }
}

static void testMultiplierOfflineQuota(void)
{
    const uint32_t multipliers[] = {500, 2000};
    const uint64_t before[] = {18, 4}, final[] = {2, 1};
    for (unsigned i = 0; i < sizeof(multipliers) / sizeof(multipliers[0]); ++i)
    {
        setup(1);
        user_update_t initial = {
            .mask = kUserUpdateStats | kUserUpdateLimit, .stats.traffic.u = 90, .limit.traffic.total = 100};
        authTestPeerSetUser(server, 42, &initial);
        startWithMultiplier(0, multipliers[i]);
        require(local(0, false) == 90, "multiplier changed downloaded server total");
        disconnect(0);
        user_handle_t handle;
        require(authenticationclientGetUserByPassword(clients[0], "account-0", &handle), "offline account lookup");
        require(! authenticationclientUserAccountTraffic(clients[0], &handle, before[i], 0, 100000),
                "charged quota closed before its limit");
        require(authenticationclientUserAccountTraffic(clients[0], &handle, final[i], 0, 100000) &&
                    local(0, false) == 100,
                "offline quota did not use charged traffic");
        require(! authenticationclientGetUserByPassword(clients[0], "account-0", &handle),
                "charged quota permitted another offline login");
        pump(10);
        pump(1);
        pump(1);
        require(authTestPeerStats(server, 42).traffic.u == 100, "reconnect multiplied charged quota usage again");
        teardown();
    }
}

static void testDiscountFirstUse(void)
{
    for (unsigned use_add_api = 0; use_add_api < 2; ++use_add_api)
    {
        setup(1);
        user_update_t update = {.mask = kUserUpdateTimeInfo, .timeinfo.expire_after_first_usage_ms = 100};
        authTestPeerSetUser(server, 42, &update);
        startWithMultiplier(0, 500);
        disconnect(0);
        user_handle_t handle = {.generation = state(0)->users_generation, .user_id = 42};
        require(authenticationclientUserAddTraffic(clients[0], &handle, 0, 0) &&
                    ! usersLookupByIdentifier(state(0)->users, 42)->client_time.observed,
                "empty traffic started first-use expiry");
        if (use_add_api)
            require(authenticationclientUserAddTraffic(clients[0], &handle, 1, 0), "discounted first upload");
        else
            require(! authenticationclientUserAccountTraffic(clients[0], &handle, 0, 1, 100000),
                    "discounted first download closed too early");
        user_t           *user        = usersLookupByIdentifier(state(0)->users, 42);
        const uint64_t    observation = user->client_time.first_report_ms;
        const user_stat_t stats       = localStats(0, 42);
        require(stats.traffic.u == 0 && stats.traffic.d == 0 && user->client_time.observed && observation != 0,
                "rounded-zero charge lost actual first traffic");
        atomicStoreU64(&now_us, 100101000);
        require(authenticationclientUserShouldClose(clients[0], &handle, 100101),
                "discounted offline first traffic did not start expiry");
        pump(10);
        pump(1);
        pump(1);
        const user_stat_t remote = authTestPeerStats(server, 42);
        require(remote.traffic.u == 0 && remote.traffic.d == 0 && authTestPeerFirstUse(server) == observation &&
                    authTestPeerSequence(server, 0) == 1,
                "metadata-only discounted first use was lost or charged a byte");
        user = usersLookupByIdentifier(state(0)->users, 42);
        require(user->client_time.observation_acked && user->client_time.first_report_ms == observation &&
                    authenticationclientUserShouldClose(clients[0], &handle, authenticationclientLocalTimeMS()),
                "discounted first-use ACK restarted expiry");
        teardown();
    }
}

static void testMultiplierRefreshAndReplay(void)
{
    setup(1);
    user_update_t initial = {.mask = kUserUpdateStats, .stats.traffic.u = 20};
    authTestPeerSetUser(server, 42, &initial);
    startWithMultiplier(0, 500);
    user_handle_t handle = {.generation = state(0)->users_generation, .user_id = 42};
    require(authenticationclientUserAddTraffic(clients[0], &handle, 3, 1), "discounted initial traffic");
    require(localStats(0, 42).traffic.u == 21 && localStats(0, 42).traffic.d == 0,
            "initial fractional charge was wrong");
    drop_ack = 1;
    authenticationclientRequestPush(clients[0]);
    require(state(0)->pending_batch != NULL && authTestPeerStats(server, 42).traffic.u == 21,
            "lost-ACK discounted batch did not commit");
    require(! authenticationclientUserAccountTraffic(clients[0], &handle, 2, 2, 100000), "offline post-batch traffic");
    pump(10);
    pump(1);
    pump(1);
    require(state(0)->pending_batch == NULL && authTestPeerSequence(server, 0) == 2 &&
                authTestPeerStats(server, 42).traffic.u == 22 && authTestPeerStats(server, 42).traffic.d == 1,
            "replay changed charged deltas or lost post-batch traffic");
    authenticationclientRequestPull(clients[0]);
    require(! authenticationclientUserAccountTraffic(clients[0], &handle, 1, 1, authenticationclientLocalTimeMS()),
            "fractional traffic after refreshed ACK");
    require(localStats(0, 42).traffic.u == 23 && localStats(0, 42).traffic.d == 2,
            "ACK, refresh or reconnect discarded fractional remainder");
    authenticationclientRequestPush(clients[0]);
    pump(1);
    require(authTestPeerStats(server, 42).traffic.u == 23 && authTestPeerStats(server, 42).traffic.d == 2,
            "charged remainder was multiplied again on synchronization");
    teardown();
}

static void testMultiplierSharedServerTotals(void)
{
    setup(1);
    user_update_t initial = {.mask = kUserUpdateStats, .stats.traffic.u = 100};
    authTestPeerSetUser(server, 42, &initial);
    startWithMultiplier(0, 500);
    startWithMultiplier(1, 2000);
    for (unsigned i = 0; i < 2; ++i)
    {
        user_handle_t handle = {.generation = state(i)->users_generation, .user_id = 42};
        require(authenticationclientUserAddTraffic(clients[i], &handle, 3, 5), "different-rate producer traffic");
        authenticationclientRequestPush(clients[i]);
    }
    authenticationclientRequestPull(clients[0]);
    authenticationclientRequestPull(clients[1]);
    for (unsigned i = 0; i < 2; ++i)
    {
        const user_stat_t stats = localStats(i, 42);
        require(stats.traffic.u == 107 && stats.traffic.d == 12,
                "client multiplied aggregate charges from another producer");
    }
    require(authTestPeerStats(server, 42).traffic.u == 107 && authTestPeerStats(server, 42).traffic.d == 12,
            "different producer multipliers did not aggregate exact charges");
    user_handle_t handle = {.generation = state(0)->users_generation, .user_id = 42};
    require(authenticationclientUserAddTraffic(clients[0], &handle, 1, 1), "discounted remainder after remote update");
    require(localStats(0, 42).traffic.u == 108 && localStats(0, 42).traffic.d == 13,
            "other producer's traffic erased local fractional remainder");
    authenticationclientRequestPush(clients[0]);
    require(authTestPeerStats(server, 42).traffic.u == 108 && authTestPeerStats(server, 42).traffic.d == 13,
            "discounted remainder did not synchronize as charged bytes");
    teardown();
}

static void testDiscountConcurrentRefresh(void)
{
    setup(1);
    startWithMultiplier(0, 500);
    traffic(0, 1);
    authenticationclientRequestPush(clients[0]);
    require(local(0, false) == 0 && authTestPeerFirstUse(server) != 0, "concurrent discount metadata-only setup");
    user_handle_t             handle      = {.generation = state(0)->users_generation, .user_id = 42};
    refresh_traffic_context_t contexts[2] = {{.handle = handle}, {.handle = handle}};
    pthread_t                 threads[2];
    for (unsigned i = 0; i < 2; ++i)
    {
        atomic_init(&contexts[i].started, false);
        atomic_init(&contexts[i].stop, false);
        atomic_init(&contexts[i].finished, false);
        atomic_init(&contexts[i].produced, 0);
        require(pthread_create(&threads[i], NULL, trafficDuringRefresh, &contexts[i]) == 0,
                "concurrent discount traffic thread");
    }
    for (unsigned attempts = 0;
         attempts < 1000 && (atomic_load(&contexts[0].produced) == 0 || atomic_load(&contexts[1].produced) == 0);
         ++attempts)
        wwSleepMS(1);
    require(atomic_load(&contexts[0].produced) != 0 && atomic_load(&contexts[1].produced) != 0,
            "both fractional traffic producers did not start");
    for (unsigned i = 0; i < 8; ++i)
        authenticationclientRequestPull(clients[0]);
    for (unsigned i = 0; i < 2; ++i)
        atomic_store(&contexts[i].stop, true);
    for (unsigned i = 0; i < 2; ++i)
        require(pthread_join(threads[i], NULL) == 0, "concurrent discount thread join");
    const uint64_t raw = 1 + (uint64_t) atomic_load(&contexts[0].produced) + atomic_load(&contexts[1].produced);
    require(local(0, false) == raw / 2, "concurrent traffic or refresh lost/doubled fractional carry");
    require(! authenticationclientUserAccountTraffic(clients[0], &handle, 1, 0, 0) && local(0, false) == (raw + 1) / 2,
            "concurrent refresh did not preserve the final fractional carry");
    authenticationclientRequestPush(clients[0]);
    require(authTestPeerStats(server, 42).traffic.u == (raw + 1) / 2,
            "concurrent discounted charges did not reconcile exactly");
    teardown();
}

static void requireSyncPhase(const char *expected)
{
    cJSON       *status = statusBody("{}", 1024 * 1024, kApiResultOk);
    const cJSON *phase  = cJSON_GetObjectItemCaseSensitive(status, "sync_phase");
    require(cJSON_IsString(phase) && strcmp(phase->valuestring, expected) == 0,
            "basic status synchronization phase does not match pending work");
    require(strcmp(cJSON_GetObjectItemCaseSensitive(status, "accounting_state")->valuestring, "not_requested") == 0,
            "basic phase lookup requested detailed accounting");
    cJSON_Delete(status);
}

static void testStatusSnapshot(void)
{
    setup(1);
    hold_pull = true;
    start(0);
    require(authenticationclientRegisterApi(clients[0]), "status registration failed");
    authenticationclient_status_t snapshot;
    authenticationclientStatusSnapshot(clients[0], false, 0, 0, &snapshot);
    require(snapshot.authenticated && snapshot.pull_in_flight && ! snapshot.can_authenticate &&
                snapshot.blocking_reason == kAuthenticationClientBlockCacheClock && snapshot.auth_success_valid &&
                ! snapshot.pull_success_valid && ! snapshot.ack_success_valid &&
                snapshot.accounting_state == kAuthenticationClientAccountingNotRequested,
            "status conflated cache, connection and required refresh");
    deliverHeldRequest();
    require(state(0)->last_pull_success_valid && ! state(0)->last_ack_success_valid,
            "pull success timestamp did not track commit");
    disconnect(0);
    user_handle_t handle;
    userHandleSet(&handle, state(0)->users_generation, 42);
    require(! authenticationclientUserAccountTraffic(clients[0], &handle, 20, 30, 100000), "offline status traffic");
    authenticationclient_tstate_t *ts = state(0);
    ts->pending_entries               = memoryAllocate(sizeof(*ts->pending_entries));
    ts->pending_entries_count         = 1;
    ts->pending_entries[0]            = (authenticationclient_accounting_entry_t) {
                   .id = 42, .totals = {.u = 10, .d = 20}, .delta = {.u = 10, .d = 20}, .first_usage_at_ms = 1};
    ts->pending_batch         = stringDuplicate("{\"private_batch\":true}");
    ts->pending_batch_length  = (uint32_t) strlen(ts->pending_batch);
    ts->catchup_entries       = memoryCalloc(3, sizeof(*ts->catchup_entries));
    ts->catchup_entries_count = 3;
    ts->catchup_entries[0] =
        (authenticationclient_accounting_entry_t) {.id = 42, .delta = {.u = 15, .d = 25}, .first_usage_at_ms = 1};
    ts->catchup_entries[1] =
        (authenticationclient_accounting_entry_t) {.id = 99, .delta = {.u = 3, .d = 4}, .first_usage_at_ms = 1};
    ts->catchup_entries[2].id = 100; /* Settled retained slot must not inflate owed-user count. */
    const bool                                    push_requested = ts->push_requested;
    const uint64_t                                sequence       = ts->next_batch_sequence;
    const authenticationclient_accounting_entry_t pending        = ts->pending_entries[0];
    authenticationclientStatusSnapshot(clients[0], true, 1024 * 1024, 0, &snapshot);
    require(snapshot.can_authenticate && ! snapshot.connected && snapshot.unresolved_batch &&
                snapshot.accounting_state == kAuthenticationClientAccountingAvailable &&
                snapshot.locally_unacknowledged_upload_bytes == 23 &&
                snapshot.locally_unacknowledged_download_bytes == 34 && snapshot.usage_user_count == 2 &&
                snapshot.first_use_observation_count == 2 && ! snapshot.accounting_lower_bound,
            "status duplicated overlapping debt or lost retained-only debt");
    for (unsigned i = 0; i < 3; ++i)
    {
        cJSON       *json   = statusBody("{\"include_accounting\":true}", 1024 * 1024, kApiResultOk);
        const cJSON *amount = cJSON_GetObjectItemCaseSensitive(json, "locally_unacknowledged_upload_bytes");
        require(cJSON_IsString(amount) && strcmp(amount->valuestring, "23") == 0 &&
                    cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "can_authenticate")) &&
                    cJSON_GetObjectItemCaseSensitive(json, "users") == NULL &&
                    cJSON_GetObjectItemCaseSensitive(json, "accounting_epoch") == NULL,
                "status amounts were inexact or private data escaped");
        char *text = cJSON_PrintUnformatted(json);
        require(strstr(text, "account-0") == NULL && strstr(text, "private_batch") == NULL &&
                    strstr(text, "secret") == NULL,
                "status leaked account or protocol contents");
        cJSON_free(text);
        cJSON_Delete(json);
    }
    require(ts->push_requested == push_requested && ts->next_batch_sequence == sequence &&
                memcmp(&pending, ts->pending_entries, sizeof(pending)) == 0 && local(0, false) == 20 &&
                local(0, true) == 0,
            "status changed synchronization or baseline state");
    user_stat_t rebased = {.traffic = {.u = 20, .d = 30}};
    require(usersSetUserStats(ts->sync_baseline_users, usersLookupByIdentifier(ts->sync_baseline_users, 42), &rebased),
            "status rebased-baseline setup");
    authenticationclientStatusSnapshot(clients[0], true, 1024 * 1024, 0, &snapshot);
    require(snapshot.locally_unacknowledged_upload_bytes == 23 && snapshot.locally_unacknowledged_download_bytes == 34,
            "status lost immutable pending debt plus later traffic when visible delta disappeared");
    authenticationclientStatusSnapshot(clients[0], true, 0, 0, &snapshot);
    require(snapshot.accounting_state == kAuthenticationClientAccountingUnavailable && snapshot.can_authenticate,
            "accounting budget refusal removed basic availability");
    authenticationclientStatusSnapshot(clients[0], true, 1024 * 1024, authenticationclientLocalTimeMS(), &snapshot);
    require(snapshot.accounting_state == kAuthenticationClientAccountingUnavailable,
            "expired accounting scan did not refuse work");

    /* A pending timestamp alone is not an outstanding first-use observation. */
    user_t *active = usersLookupByIdentifier(ts->users, 42);
    userAcknowledgeObservation(active, active->client_time.first_report_ms);
    ts->catchup_entries[0].first_usage_at_ms = 0;
    ts->catchup_entries[1].first_usage_at_ms = 0;
    ts->catchup_entries[1].delta.u           = UINT64_MAX;
    authenticationclientStatusSnapshot(clients[0], true, 1024 * 1024, 0, &snapshot);
    require(snapshot.first_use_observation_count == 0 && snapshot.accounting_lower_bound &&
                snapshot.locally_unacknowledged_upload_bytes == UINT64_MAX,
            "status lost saturation or invented pending observations");
    user_stat_t stats = {0};
    stats.traffic.u   = UINT64_MAX;
    require(
        usersSetUserStats(ts->users, active, &stats) &&
            usersSetUserStats(ts->sync_baseline_users, usersLookupByIdentifier(ts->sync_baseline_users, 42), &stats),
        "status saturated-counter setup");
    ts->pending_entries[0].delta  = (user_ud_t) {0};
    ts->pending_entries[0].totals = stats.traffic;
    ts->catchup_entries[0].delta = ts->catchup_entries[1].delta = (user_ud_t) {0};
    authenticationclientStatusSnapshot(clients[0], true, 1024 * 1024, 0, &snapshot);
    require(snapshot.locally_unacknowledged_upload_bytes == 0 && snapshot.accounting_lower_bound,
            "exhausted counters reported false exact zero debt");
    ts->auth_rejected = ts->continuity_error = ts->stopping = true;
    authenticationclientStatusSnapshot(clients[0], false, 0, 0, &snapshot);
    require(snapshot.blocking_reason == kAuthenticationClientBlockStopping, "status blocking precedence stopping");
    ts->stopping = false;
    ts->started  = false;
    authenticationclientStatusSnapshot(clients[0], false, 0, 0, &snapshot);
    require(snapshot.blocking_reason == kAuthenticationClientBlockNotStarted, "status blocking precedence startup");
    ts->started = true;
    authenticationclientStatusSnapshot(clients[0], false, 0, 0, &snapshot);
    require(snapshot.blocking_reason == kAuthenticationClientBlockContinuity, "status blocking precedence continuity");
    ts->continuity_error = false;
    authenticationclientStatusSnapshot(clients[0], false, 0, 0, &snapshot);
    require(snapshot.blocking_reason == kAuthenticationClientBlockCredentialRejected,
            "status blocking precedence credential rejection");
    ts->auth_rejected           = false;
    ts->last_auth_success_ms    = 0;
    ts->last_auth_success_valid = true;
    authenticationclientStatusSnapshot(clients[0], false, 0, 0, &snapshot);
    require(snapshot.auth_success_valid && snapshot.auth_success_age_ms == authenticationclientLocalTimeMS(),
            "monotonic zero success became unknown");
    const char *invalid[] = {"",
                             "[]",
                             "{} trailing",
                             "{\"unknown\":true}",
                             "{\"include_accounting\":1}",
                             "{\"include_accounting\":true,\"include_accounting\":false}",
                             "{\"include_accounting\\u0000\":true}"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        cJSON_Delete(statusBody(invalid[i], 1024 * 1024, kApiResultError));
    cJSON *basic = statusBody("{}", 1024 * 1024, kApiResultOk);
    require(strcmp(cJSON_GetObjectItemCaseSensitive(basic, "accounting_state")->valuestring, "not_requested") == 0 &&
                cJSON_GetObjectItemCaseSensitive(basic, "locally_unacknowledged_upload_bytes") == NULL,
            "basic snapshot scanned or exposed detailed accounting");
    cJSON_Delete(basic);
    teardown();
}

static void testStatusTimeoutHistory(void)
{
    setup(1);
    hold_pull = true;
    start(0);
    atomicAddU64(&now_us, 1001000);
    wloopUpdateTime(loops[0]);
    require(authenticationclientCloseTimedOutControlLine(clients[0]), "status timeout trigger failed");
    authenticationclient_status_t snapshot;
    authenticationclientStatusSnapshot(clients[0], false, 0, 0, &snapshot);
    require(snapshot.last_failure == kAuthenticationClientFailureTimeout &&
                snapshot.last_failure_operation == kAuthenticationClientRequestTypeGetAllUsers &&
                snapshot.auth_success_valid && ! snapshot.pull_success_valid,
            "transport cleanup overwrote timeout or fabricated pull success");
    teardown();

    setup(1);
    start(0);
    traffic(0, 7);
    authenticationclientRequestPush(clients[0]);
    authenticationclientStatusSnapshot(clients[0], false, 0, 0, &snapshot);
    require(snapshot.ack_success_valid && snapshot.pull_success_valid && ! snapshot.unresolved_batch,
            "status did not record committed matching ACK");
    const uint64_t ack_time = state(0)->last_ack_success_ms;
    disconnect(0);
    atomicAddU64(&now_us, 7000);
    authenticationclientStatusSnapshot(clients[0], false, 0, 0, &snapshot);
    require(snapshot.ack_success_valid && snapshot.ack_success_age_ms == authenticationclientLocalTimeMS() - ack_time,
            "disconnect discarded ACK success history");
    teardown();
}

static void testStatsRefusalRecovery(void)
{
    for (unsigned lost_ack = 0; lost_ack < 2; ++lost_ack)
    {
        setup(1);
        start(0);
        authenticationclient_tstate_t *ts = state(0);
        ts->reconnect_interval_ms         = 0;
        if (! lost_ack)
            authTestPeerPermissions(server, 0, false, false);
        else
            drop_ack = 1;
        traffic(0, 10);
        if (lost_ack)
        {
            authenticationclientRequestPush(clients[0]);
            require(authTestPeerStats(server, 42).traffic.u == 10 && ts->pending_batch != NULL,
                    "lost ACK did not retain applied usage");
            authTestPeerPermissions(server, 0, false, false);
        }
        pump(0); /* First-use and replay work run with every periodic job disabled. */
        require(ts->stats_push_refused && ! ts->continuity_error && ts->pending_batch != NULL &&
                    ts->control_line == NULL && ts->reconnect_timer != NULL &&
                    ts->last_failure == kAuthenticationClientFailureStatsPushDenied,
                "stats permission refusal became terminal or lost its independent retry");
        char                         *batch    = stringDuplicate(ts->pending_batch);
        const uint64_t                sequence = ts->next_batch_sequence;
        const unsigned                attempts = pushes, refreshes = pulls;
        const uint64_t                deadline = ts->stats_retry_not_before_ms;
        authenticationclient_status_t snapshot;
        authenticationclientStatusSnapshot(clients[0], true, 1024 * 1024, 0, &snapshot);
        require(snapshot.can_authenticate && snapshot.unresolved_batch && snapshot.retry_deadline_valid &&
                    snapshot.retry_remaining_ms == 30000 && snapshot.locally_unacknowledged_upload_bytes == 10 &&
                    snapshot.first_use_observation_count == 1,
                "refusal status lost cached admission, retained debt, first use or retry deadline");
        user_handle_t handle;
        require(authenticationclientGetUserByPassword(clients[0], "account-0", &handle),
                "stats refusal blocked cached credentials");
        user_ip_key_t ip = {.type = 4, .bytes = {192, 0, 2, 1}};
        require(authenticationclientUserTryAdmitConnection(clients[0], &handle, &ip, 100000) == kUserAdmissionOk,
                "stats refusal blocked cached reservation");
        authenticationclientUserReleaseConnection(clients[0], &handle, &ip);
        traffic(0, 5);
        for (unsigned i = 0; i < 10; ++i)
        {
            authenticationclientRequestPush(clients[0]);
            authenticationclientResumeSync(clients[0]);
            authenticationclientOpenControlLine(clients[0]);
            authenticationclientScheduleReconnect(clients[0]);
            pump(0);
        }
        pump(29999);
        require(pushes == attempts && pulls == refreshes && ts->control_line == NULL &&
                    ts->stats_retry_not_before_ms == deadline && ts->next_batch_sequence == sequence &&
                    strcmp(ts->pending_batch, batch) == 0 && ts->progress_timer == NULL,
                "traffic or explicit/reentrant work bypassed refusal cooldown or changed the batch");
        pump(1);
        require(pushes == attempts + 1 && pulls == refreshes && ts->stats_push_refused && ! ts->continuity_error &&
                    strcmp(ts->pending_batch, batch) == 0,
                "due refusal retry did not preserve one exact batch attempt");
        authTestPeerPermissions(server, 0, false, true);
        pause_before_session = true;
        pump(30000);
        require(ts->authenticated && ts->stats_push_refused && ts->pending_batch != NULL && ts->write_paused,
                "successful Session cleared refusal before its matching ACK");
        authenticationclientTunnelDownStreamResume(clients[0], ts->control_line);
        for (unsigned i = 0; i < 4; ++i)
            pump(1);
        require(! ts->stats_push_refused && ts->pending_batch == NULL && ts->next_batch_sequence == sequence + 2 &&
                    authTestPeerStats(server, 42).traffic.u == 15 && local(0, true) == 15 && local(0, false) == 15,
                "same-epoch recovery duplicated/dropped retained or later usage");
        memoryFree(batch);
        teardown();
    }

    setup(1);
    start(0);
    state(0)->reconnect_interval_ms = 60000;
    authTestPeerPermissions(server, 0, false, false);
    traffic(0, 1);
    pump(0);
    const unsigned attempts = pushes;
    pump(30000);
    require(pushes == attempts && state(0)->reconnect_timer != NULL,
            "refusal ignored larger configured reconnect interval");
    pump(30000);
    require(pushes == attempts + 1, "larger configured refusal deadline did not retry");
    teardown(); /* Quiescence must cancel an outstanding refusal retry. */
}

static void testFirstUseDeferredByPull(void)
{
    setup(128);
    start(0);
    hold_pull = true;
    authenticationclientRequestPull(clients[0]);
    require(held_request != NULL && state(0)->pull_in_flight, "first-use pull was not held");
    testWorkerBindWID(1);
    for (unsigned pass = 0; pass < 5; ++pass)
        for (uint64_t id = 42; id < 42 + 128; ++id)
        {
            user_handle_t handle = {.generation = state(0)->users_generation, .user_id = id};
            require(authenticationclientUserAddTraffic(clients[0], &handle, 1, 0), "first-use traffic failed");
        }
    testWorkerBindWID(0);
    pump(0);
    require(state(0)->first_usage_push_requested && state(0)->first_usage_push_deferred && state(0)->push_requested &&
                pushes == 0 && state(0)->progress_timer == NULL,
            "held pull repeatedly reset or scheduled first-use reporting");
    for (size_t i = 0; i < usersCount(state(0)->users); ++i)
        require(usersGetAt(state(0)->users, i)->runtime.first_usage_push_requested,
                "held pull reset a user's first-use request flag");
    deliverHeldRequest();
    for (unsigned i = 0; i < 4; ++i)
        pump(1);
    require(pushes == 1 && state(0)->pending_batch == NULL, "pull completion needed another packet to report");
    for (uint64_t id = 42; id < 42 + 128; ++id)
        require(authTestPeerStats(server, id).traffic.u == 5, "deferred first-use report lost usage");
    teardown();
}

static void testPagedTablesAndAggregateLimits(void)
{
    setup(3);
    /* Three bounded large rows make the aggregate exceed the old 16 MiB
     * envelope without thousands of expensive crypto constructions. */
    const size_t note_length = 6U * 1024U * 1024U;
    char        *notes       = memoryAllocate(note_length + 1);
    memset(notes, 'p', note_length);
    notes[note_length] = '\0';
    for (uint64_t id = 42; id < 45; ++id)
    {
        user_update_t update = {.mask = kUserUpdateNotes, .notes = notes};
        authTestPeerSetUser(server, id, &update);
    }
    memoryFree(notes);
    start(0);
    require(state(0)->users_loaded && usersCount(state(0)->users) == 3 && page_requests == 4 &&
                ! state(0)->staging.active && ! state(0)->pull_required,
            ">16 MiB paired table did not install through three pages and final validation");
    for (uint64_t id = 42; id < 45; ++id)
        require(strlen(usersLookupByIdentifier(state(0)->users, id)->notes) == note_length,
                "exceptional page truncated a full record");
    require(state(0)->sync_retry_streak == 0, "successful final installation did not clear failed-sync streak");
    teardown();

    setup(129);
    start(0);
    require(usersCount(state(0)->users) == 129 && page_requests == 3,
            "128-row page boundary did not make positional progress");
    const uint64_t generation = state(0)->users_generation;
    state(0)->sync_max_users  = 128;
    authenticationclientRequestPull(clients[0]);
    require(state(0)->users_generation == generation && authenticationclientCanAuthenticate(clients[0]) &&
                state(0)->last_failure == kAuthenticationClientFailureSyncLimit && ! state(0)->staging.active,
            "declared count limit replaced cache or retained staging");
    state(0)->sync_max_users = 129;
    pump(1000);
    require(state(0)->users_generation == generation + 1, "count equality did not recover");
    hold_final_page = true;
    authenticationclientRequestPull(clients[0]);
    require(held_request != NULL && state(0)->staging.complete, "byte-equality traversal not held at validation");
    const uint64_t exact_bytes = state(0)->staging.encoded_bytes;
    deliverHeldRequest();
    state(0)->sync_max_bytes = exact_bytes;
    authenticationclientRequestPull(clients[0]);
    require(! state(0)->staging.active && state(0)->last_pull_success_valid,
            "exact aggregate-byte boundary was refused");
    const uint64_t installed = state(0)->users_generation;
    state(0)->sync_max_bytes = exact_bytes - 1;
    authenticationclientRequestPull(clients[0]);
    require(state(0)->users_generation == installed &&
                state(0)->last_failure == kAuthenticationClientFailureSyncLimit &&
                authenticationclientCanAuthenticate(clients[0]) && ! state(0)->staging.active,
            "one-over aggregate bytes changed active cache");
    teardown();
}

static void testPagedConfigurationAndLiveDeltas(void)
{
    setup(257);
    start(0);
    const uint64_t generation = state(0)->users_generation;
    hold_page_position        = 128;
    authenticationclientRequestPull(clients[0]);
    require(held_request != NULL && state(0)->staging.position == 128 && state(0)->staging.active &&
                state(0)->users_generation == generation && authenticationclientCanAuthenticate(clients[0]),
            "intermediate page exposed a partial table");
    const unsigned before_pushes = pushes;
    for (uint64_t id = 42; id <= 42 + 256; id += 256)
    {
        user_handle_t handle = {.generation = generation, .user_id = id};
        require(authenticationclientUserAddTraffic(clients[0], &handle, 7, 3), "traffic during paging failed");
    }
    authenticationclientRequestPush(clients[0]);
    pump(0);
    require(pushes == before_pushes && state(0)->pending_batch == NULL && state(0)->pull_required,
            "new usage batch crossed the traversal barrier");
    pump(400);
    deliverHeldRequest();
    for (unsigned i = 0; i < 4; ++i)
        pump(1);
    require(authTestPeerStats(server, 42).traffic.u == 7 && authTestPeerStats(server, 42 + 256).traffic.u == 7 &&
                authTestPeerStats(server, 42).traffic.d == 3 && authTestPeerSequence(server, 0) == 1,
            "early/late page traffic was not reported exactly once");
    require(! state(0)->staging.active && ! state(0)->pull_required && state(0)->pending_batch == NULL,
            "post-paging ACK refresh did not settle");

    const uint64_t stable = state(0)->users_generation;
    hold_page_position    = 128;
    authenticationclientRequestPull(clients[0]);
    authTestPeerPassword(server);
    deliverHeldRequest();
    require(state(0)->users_generation == stable + 1 && ! state(0)->staging.active &&
                authenticationclientCanAuthenticate(clients[0]),
            "config edit invalidated the retained traversal snapshot");
    authenticationclientRequestPull(clients[0]);
    require(state(0)->users_generation == stable + 2 && state(0)->sync_retry_streak == 0,
            "later traversal did not install the edited snapshot");
    user_handle_t handle;
    require(authenticationclientGetUserByPassword(clients[0], "changed", &handle), "coherent edited credential absent");

    const uint64_t validated = state(0)->users_generation;
    hold_final_page          = true;
    authenticationclientRequestPull(clients[0]);
    require(held_request != NULL && state(0)->staging.complete, "final validation was not independently pending");
    authTestPeerSetConfigRevision(server, state(0)->staging.config_revision + 1);
    deliverHeldRequest();
    require(state(0)->users_generation == validated + 1 && ! state(0)->staging.active &&
                authenticationclientCanAuthenticate(clients[0]),
            "edit before validation invalidated an immutable snapshot");
    teardown();
}

static void testPagingDisconnectAndAbsoluteDeadlines(void)
{
    setup(257);
    start(0);
    for (unsigned boundary = 0; boundary < 4; ++boundary)
    {
        const uint64_t generation = state(0)->users_generation;
        if (boundary == 3)
            hold_final_page = true;
        else
            hold_page_position = (uint64_t) boundary * 128;
        authenticationclientRequestPull(clients[0]);
        require(held_request != NULL && state(0)->staging.active, "boundary request not retained");
        sbufDestroy(held_request);
        held_request = NULL;
        disconnect(0);
        require(! state(0)->staging.active && state(0)->users_generation == generation &&
                    authenticationclientCanAuthenticate(clients[0]),
                "disconnect discarded active cache");
        pump(10);
        require(state(0)->users_generation == generation + 1, "boundary disconnect failed to restart traversal");
    }
    const uint64_t generation = state(0)->users_generation;
    hold_page_position        = 128;
    authenticationclientRequestPull(clients[0]);
    pump(700);
    hold_page_position = 256;
    deliverHeldRequest();
    require(held_request != NULL, "second delayed page not held");
    pump(700);
    hold_final_page = true;
    deliverHeldRequest();
    require(held_request != NULL && state(0)->staging.complete, "delayed final validation not held");
    pump(700);
    deliverHeldRequest();
    require(state(0)->users_generation == generation + 1 && ! state(0)->staging.active,
            "progressing traversal inherited a whole-table absolute timeout");
    hold_page_position = 128;
    authenticationclientRequestPull(clients[0]);
    pump(1000);
    require(! state(0)->staging.active && state(0)->last_failure == kAuthenticationClientFailureTimeout &&
                authenticationclientCanAuthenticate(clients[0]),
            "stalled individual page did not time out");
    sbufDestroy(held_request);
    held_request = NULL;
    teardown();
}

static void testPerPageClockInstallation(void)
{
    setup(257);
    const user_update_t expiry = {.mask = kUserUpdateTimeInfo, .timeinfo.expire_at_ms = 1000600};
    authTestPeerSetUser(server, 42, &expiry);
    authTestPeerSetUser(server, 42 + 256, &expiry);
    hold_page_position = 128;
    start(0);
    require(held_request != NULL && state(0)->staging.position == 128 && ! state(0)->users_loaded,
            "fresh multi-page clock fixture not staged");
    /* Server wall time stands still while local monotonic time advances, as
     * with a wall correction. Early records must retain their earlier receipt. */
    atomicStoreU64(&client_wall_ms, 1);
    pump(700);
    deliverHeldRequest();
    user_t *early = usersLookupByIdentifier(state(0)->users, 42);
    user_t *late  = usersLookupByIdentifier(state(0)->users, 42 + 256);
    require(early != NULL && late != NULL && early->client_time.local_anchor_ms == 100000 &&
                early->client_view_expired && late->client_view_expires_at_ms == 101300 &&
                userRuntimeShouldClose(early, 100700) && ! userRuntimeShouldClose(late, 100700),
            "page clocks used the final page receipt for every user or followed the local wall");
    user_handle_t handle;
    require(! authenticationclientGetUserByPassword(clients[0], "account-0", &handle),
            "early-page expired account admitted after delayed installation");
    teardown();
}

static void testPagingPreservesRuntimeAndFractionalCarry(void)
{
    setup(257);
    startWithMultiplier(0, 500);
    user_handle_t handle = {.generation = state(0)->users_generation, .user_id = 42};
    user_ip_key_t ip     = {.type = 4, .bytes = {192, 0, 2, 9}};
    require(authenticationclientUserTryAdmitConnection(clients[0], &handle, &ip, 100000) == kUserAdmissionOk,
            "page runtime admission fixture");
    const uint64_t ticket = authenticationclientUserBandwidthRegister(clients[0], &handle, kUserBandwidthUpload);
    const buffer_budget_cost_t cost = {.bytes = 12, .charge = 64, .entries = 1};
    require(ticket != 0 && authenticationclientUserBandwidthReserve(clients[0], &handle, ticket, cost),
            "page runtime queue fixture");
    authenticationclientUserBandwidthSetEligible(clients[0], &handle, kUserBandwidthUpload, ticket, true);
    hold_page_position = 128;
    authenticationclientRequestPull(clients[0]);
    require(held_request != NULL, "runtime traversal boundary not held");
    require(! authenticationclientUserObservePayload(clients[0], &handle, 1, 0, 100000),
            "page arrival observation rejected");
    require(authenticationclientUserCommitDelivery(clients[0], &handle, kUserBandwidthUpload, ticket, 1, false, true) ==
                kUserDeliveryForward,
            "page delivery fixture did not forward");
    user_t        *before = usersLookupByIdentifier(state(0)->users, 42);
    const uint64_t origin = before->client_time.first_report_ms;
    require(before->runtime.traffic_remainder_u == 500 && origin != 0, "fractional observation fixture");
    pump(400);
    deliverHeldRequest();
    user_t *after = usersLookupByIdentifier(state(0)->users, 42);
    require(after->runtime.active_cons_out == 1 && after->runtime.ip_usage_count == 1 &&
                after->runtime.traffic_remainder_u == 500 && after->client_time.first_report_ms == origin &&
                after->runtime.queued_cost.bytes == cost.bytes && state(0)->bandwidth_queued_cost.bytes == cost.bytes,
            "paging lost current carry/observation/admission/shaping state");
    require(authenticationclientUserBandwidthPreview(clients[0], &handle, kUserBandwidthUpload, ticket, 1, false)
                    .decision == kUserDeliveryForward,
            "migrated shaping ticket lost its fair turn");
    require(authenticationclientUserCommitDelivery(
                clients[0], &handle, kUserBandwidthUpload, ticket, 1, false, false) == kUserDeliveryForward,
            "delivery after paged migration failed");
    require(after->runtime.traffic_remainder_u == 0 && local(0, false) == 1,
            "fractional charge was reset or applied twice across pages");
    authenticationclientUserBandwidthCancel(clients[0], &handle, kUserBandwidthUpload, ticket);
    authenticationclientUserReleaseConnection(clients[0], &handle, &ip);
    require(state(0)->bandwidth_ticket_count == 0 && state(0)->bandwidth_queued_cost.bytes == 0 &&
                after->runtime.active_cons_out == 0,
            "migrated runtime owners did not release");
    authenticationclientRequestPush(clients[0]);
    for (unsigned i = 0; i < 4; ++i)
        pump(1);
    require(authTestPeerStats(server, 42).traffic.u == 1, "fractional paged usage was not charged exactly once");
    teardown();
}

static void testStatisticsMayChangeBetweenPages(void)
{
    setup(257);
    start(0);
    start(1);
    hold_page_position = 128;
    authenticationclientRequestPull(clients[0]);
    require(held_request != NULL, "statistics traversal boundary not held");
    const uint64_t first_stats = state(0)->staging.stats_revision;
    const unsigned traversals  = pulls;
    user_handle_t  remote      = {.generation = state(1)->users_generation, .user_id = 42 + 256};
    require(authenticationclientUserAddTraffic(clients[1], &remote, 15, 0), "foreign stats fixture");
    authenticationclientRequestPush(clients[1]);
    require(authTestPeerStats(server, 42 + 256).traffic.u == 15, "foreign stats not accepted");
    const unsigned after_foreign = pulls;
    deliverHeldRequest();
    user_t     *late = usersLookupByIdentifier(state(0)->users, 42 + 256);
    user_stat_t stats, baseline;
    userGetStats(late, &stats);
    userGetStats(usersLookupByIdentifier(state(0)->sync_baseline_users, 42 + 256), &baseline);
    require(! state(0)->staging.active && state(0)->local_stats_revision == first_stats &&
                state(0)->remote_stats_revision > first_stats && stats.traffic.u == 0 && baseline.traffic.u == 0 &&
                pulls == after_foreign && after_foreign > traversals,
            "stats-only update restarted paging or became local debt");
    const unsigned attempts = page_requests;
    pump(1);
    authenticationclientResumeSync(clients[0]);
    require(page_requests == attempts && state(0)->progress_timer == NULL,
            "mixed-time stats revision started an immediate refresh loop");
    teardown();
}

static void testOrphanDebtAndProvedBatchRejection(void)
{
    for (unsigned fault = 0; fault < 3; ++fault)
    {
        setup(2);
        start(0);
        user_handle_t removed   = {.generation = state(0)->users_generation, .user_id = 42};
        user_handle_t surviving = {.generation = state(0)->users_generation, .user_id = 43};
        user_ip_key_t ip        = {.type = 4, .bytes = {192, 0, 2, 44}};
        require(authenticationclientUserTryAdmitConnection(clients[0], &removed, &ip, 100000) == kUserAdmissionOk,
                "removed-account reservation fixture");
        const uint64_t ticket = authenticationclientUserBandwidthRegister(clients[0], &removed, kUserBandwidthUpload);
        const buffer_budget_cost_t cost = {.bytes = 1, .charge = 64, .entries = 1};
        require(ticket != 0 && authenticationclientUserBandwidthReserve(clients[0], &removed, ticket, cost),
                "removed-account shaping fixture");
        require(authenticationclientUserAddTraffic(clients[0], &removed, 7, 0) &&
                    authenticationclientUserAddTraffic(clients[0], &surviving, 9, 0),
                "removed-account traffic");
        authTestPeerRemoveUser(server);
        missing_proof_fault = fault;
        hold_final_page     = fault == 0;
        authenticationclientRequestPush(clients[0]);
        if (fault != 0)
        {
            require(state(0)->pending_batch != NULL && state(0)->next_batch_sequence == 1 &&
                        authTestPeerSequence(server, 0) == 0 && state(0)->orphan_debt_count == 0 &&
                        authTestPeerStats(server, 43).traffic.u == 0,
                    "unmatched rejection proof settled an uncertain batch or consumed debt");
            authenticationclientUserReleaseConnection(clients[0], &removed, &ip);
            authenticationclientUserBandwidthCancel(clients[0], &removed, kUserBandwidthUpload, ticket);
            teardown();
            continue;
        }
        require(held_request != NULL && state(0)->pending_batch == NULL && state(0)->next_batch_sequence == 1 &&
                    state(0)->orphan_debt_count == 1 && authTestPeerSequence(server, 0) == 0,
                "proved no-commit response advanced the checkpoint or lost the refresh barrier");
        user_handle_t lookup;
        require(! authenticationclientGetUserByPassword(clients[0], "account-0", &lookup) &&
                    authenticationclientUserTryAdmitConnection(clients[0], &removed, &ip, 100000) ==
                        kUserAdmissionInvalid &&
                    authenticationclientUserShouldClose(clients[0], &removed, 100000) &&
                    authenticationclientUserCommitDelivery(
                        clients[0], &removed, kUserBandwidthUpload, ticket, 1, false, false) == kUserDeliveryReject,
                "authoritatively absent account admitted or forwarded after rejection proof");
        require(authenticationclientUserAccountTraffic(clients[0], &removed, 3, 0, 100000),
                "already-produced orphan traffic did not request connection closure");
        deliverHeldRequest();
        for (unsigned i = 0; i < 8; ++i)
            pump(1);
        require(usersLookupByIdentifier(state(0)->users, 42) == NULL && state(0)->orphan_debt_count == 1 &&
                    state(0)->pending_batch == NULL && authTestPeerStats(server, 43).traffic.u == 9 &&
                    authTestPeerSequence(server, 0) == 1,
                "removed ID stalled survivor reporting or duplicated the reconstructed batch");
        authenticationclient_status_t status;
        authenticationclientStatusSnapshot(clients[0], true, 1024 * 1024, 0, &status);
        require(status.orphan_debt_count == 1 && status.locally_unacknowledged_upload_bytes == 10,
                "orphan status lost already-produced usage");
        const unsigned attempts = pushes;
        for (unsigned i = 0; i < 20; ++i)
            pump(1);
        require(pushes == attempts && state(0)->progress_timer == NULL, "orphan-only debt spun reporting work");
        authTestPeerInsertUser(server, 42, "account-0");
        authenticationclientRequestPull(clients[0]);
        for (unsigned i = 0; i < 8; ++i)
            pump(1);
        require(state(0)->orphan_debt_count == 0 && state(0)->catchup_entries_count == 0 &&
                    authTestPeerStats(server, 42).traffic.u == 10 && authTestPeerStats(server, 43).traffic.u == 9 &&
                    state(0)->pending_batch == NULL,
                "returning durable ID lost or duplicated retained orphan debt");
        user_handle_t recreated;
        require(authenticationclientGetUserByPassword(clients[0], "account-0", &recreated) &&
                    authenticationclientUserTryAdmitConnection(clients[0], &recreated, &ip, 100000) == kUserAdmissionOk,
                "recreated account admission fixture");
        authenticationclientUserReleaseConnection(clients[0], &removed, &ip);
        authenticationclientUserBandwidthCancel(clients[0], &removed, kUserBandwidthUpload, ticket);
        user_t *recreated_user = usersLookupByIdentifier(state(0)->users, 42);
        require(recreated_user->runtime.active_cons_out == 1 && state(0)->bandwidth_ticket_count == 0 &&
                    state(0)->bandwidth_queued_cost.bytes == 0 &&
                    authenticationclientUserAccountTraffic(clients[0], &removed, 100, 0, 100000) &&
                    authenticationclientUserShouldClose(clients[0], &removed, 100000) && local(0, false) == 10,
                "pre-removal handle consumed recreated capacity or charged the new account");
        require(! authenticationclientUserAccountTraffic(clients[0], &surviving, 1, 0, 100000),
                "ordinary refresh revoked a continuously present handle");
        authenticationclientUserReleaseConnection(clients[0], &recreated, &ip);
        require(recreated_user->runtime.active_cons_out == 0, "new account reservation did not release");
        teardown();
    }
}

static void testOrphanFirstUseAge(void)
{
    for (unsigned acknowledged = 0; acknowledged < 2; ++acknowledged)
    {
        setup(1);
        start(0);
        if (acknowledged)
        {
            traffic(0, 3);
            authenticationclientRequestPush(clients[0]);
        }
        traffic(0, 5);
        user_t        *before = usersLookupByIdentifier(state(0)->users, 42);
        const uint64_t origin = before->client_time.first_local_ms;
        const uint64_t report = before->client_time.first_report_ms;
        authTestPeerRemoveUser(server);
        authenticationclientRequestPull(clients[0]);
        require(state(0)->orphan_debt_count == 1 && state(0)->catchup_entries[0].first_usage_at_ms == report,
                "missing account lost its original first-use evidence");
        pump(250);
        authTestPeerInsertUser(server, 42, "account-0");
        const user_update_t expiry = {.mask = kUserUpdateTimeInfo, .timeinfo.expire_after_first_usage_ms = 100};
        authTestPeerSetUser(server, 42, &expiry);
        hold_push = true;
        authenticationclientRequestPull(clients[0]);
        pump(1);
        user_t       *restored = usersLookupByIdentifier(state(0)->users, 42);
        user_handle_t handle;
        require(held_request != NULL && restored->client_time.first_local_ms == origin &&
                    restored->client_time.first_report_ms == report && restored->client_view_expired &&
                    ! authenticationclientGetUserByPassword(clients[0], "account-0", &handle),
                "orphan reattachment restarted first-use expiry before its ACK");
        deliverHeldRequest();
        for (unsigned i = 0; i < 4; ++i)
            pump(1);
        require(authTestPeerStats(server, 42).traffic.u == 5 && state(0)->orphan_debt_count == 0 &&
                    state(0)->catchup_entries_count == 0,
                "orphan expiry restoration duplicated already-acknowledged traffic or lost new debt");
        teardown();
    }
}

static void testOrphanLedgerBudget(void)
{
    setup(2);
    start(0);
    authenticationclient_tstate_t *ts = state(0);
    ts->catchup_entries               = memoryCalloc(64, sizeof(*ts->catchup_entries));
    ts->catchup_entries_count = ts->orphan_debt_count = 64;
    for (size_t i = 0; i < 64; ++i)
        ts->catchup_entries[i] = (authenticationclient_accounting_entry_t) {
            .id = 1000 + i, .delta = {.u = 1}, .first_usage_at_ms = 1, .detached = true};
    const uint64_t                           generation = ts->users_generation;
    authenticationclient_accounting_entry_t *retained   = ts->catchup_entries;
    ts->sync_max_bytes                                  = 4096;
    authTestPeerRemoveUser(server);
    authenticationclientRequestPull(clients[0]);
    require(ts->last_failure == kAuthenticationClientFailureSyncLimit && ts->users_generation == generation &&
                ts->catchup_entries == retained && ts->catchup_entries_count == 64 && ts->orphan_debt_count == 64 &&
                usersLookupByIdentifier(ts->users, 42) != NULL && retained[63].delta.u == 1,
            "ledger capacity refusal changed active config or erased retained obligations");
    ts->catchup_capture_needed = true;
    authenticationclientResumeSync(clients[0]);
    const uint64_t retry = ts->catchup_retry_not_before_ms;
    require(retry > authenticationclientLocalTimeMS(), "ledger refusal had no bounded retry deadline");
    for (unsigned i = 0; i < 20; ++i)
    {
        authenticationclientResumeSync(clients[0]);
        pump(1);
        require(ts->catchup_retry_not_before_ms == retry && ts->catchup_capture_needed &&
                    ts->catchup_entries == retained && ts->progress_timer != NULL &&
                    ts->progress_timer->next_timeout / 1000 >= retry,
                "persistent ledger refusal spun or lost retained capture work");
    }
    ts->sync_max_bytes = 1024 * 1024;
    pump(1000);
    require(ts->users_generation == generation + 1 && ts->orphan_debt_count == 64 &&
                usersLookupByIdentifier(ts->users, 42) == NULL && ts->progress_timer == NULL,
            "bounded ledger retry did not preserve orphan debt while publishing config");
    teardown();
}

static void testFailedPullDoesNotStopReporting(void)
{
    setup(2);
    start(0);
    state(0)->sync_max_users = 1;
    authenticationclientRequestPull(clients[0]);
    require(state(0)->pull_deferred && ! state(0)->pull_required && state(0)->connected &&
                state(0)->last_failure == kAuthenticationClientFailureSyncLimit,
            "failed refresh retained the new-batch barrier");
    for (unsigned i = 0; i < 3; ++i)
    {
        traffic(0, 5);
        authenticationclientRequestPush(clients[0]);
        pump(1);
        require(authTestPeerStats(server, 42).traffic.u == (i + 1) * 5 && state(0)->pending_batch == NULL,
                "persistent pull limit stopped independent usage reporting");
    }
    const unsigned attempts = pulls;
    pump(1000);
    require(pulls > attempts && state(0)->pull_deferred && authenticationclientCanAuthenticate(clients[0]),
            "reporting starved the failed-refresh retry");
    state(0)->sync_max_users = 2;
    pump(1000);
    require(! state(0)->pull_deferred && ! state(0)->pull_required && state(0)->sync_retry_streak == 0 &&
                authTestPeerStats(server, 42).traffic.u == 15 && local(0, false) == 15,
            "successful refresh did not reconcile the independently reported baseline");
    teardown();
}

#include "authentication_sync_pages.h"

int main(void)
{
    testCaseSet("authentication sync loss and continuity");
    require(createNetworkLogger(NULL, false) != NULL, "logger failed");
    require(userTestRuntimeInitialize(), "crypto failed");
    testFreshEpochFailurePreservesSession();
    testResumeTokenFailurePreservesAccounting();
    testMalformedUsageAcksPreserveAccounting();
    testOrphanDebtAndProvedBatchRejection();
    testFailedPullDoesNotStopReporting();
    testOrphanLedgerBudget();
    testOrphanFirstUseAge();
    testMalformedPagesAndBackoff();
    testPerPageClockInstallation();
    testPagingPreservesRuntimeAndFractionalCarry();
    testStatisticsMayChangeBetweenPages();
    testPagedTablesAndAggregateLimits();
    testPagedConfigurationAndLiveDeltas();
    testPagingDisconnectAndAbsoluteDeadlines();
    testMultiplierSettings();
    testSyncLimitSettings();
    testCredentialSettingsLimit();
    testMultiplierFragmentAccounting();
    testMultiplierOfflineQuota();
    testDiscountFirstUse();
    testMultiplierRefreshAndReplay();
    testMultiplierSharedServerTotals();
    testDiscountConcurrentRefresh();
    testStatusSnapshot();
    testStatusTimeoutHistory();
    testStatsRefusalRecovery();
    testFirstUseDeferredByPull();
    testSharedBandwidthReservations();
    testOfflineFirstUseDeadline();
#if defined(AUTHENTICATION_SYNC_HAVE_CONTROLLER)
    testOfflineControllerExpiry();
    testControllerBandwidth();
#endif
    testTrafficDuringRefresh();
    testCatchupInterruptionAndCaptureRefusal();
    testCatchupSurvivesSaturatedRebase();
    testCatchupRecaptureMergesOverlappingTraffic();
    testOfflineLocalQuotas();
    testCachedAdmissionAndRejection();
    testInvalidClockRefresh();
    testObservationMergeAndMetadataOnly();
    testStaleFullObjectRejected();
    testConfigPatches();
    testApiProtocolPatchOrdering();
    testApiProtocolCreationOrdering();
    testApiCreationDuringOfflineCatchup();
    testConfigRevisionExhaustion();
    testApiEditDuringOfflineCatchup();
    testApiPasswordDuringOfflineCatchup();
    testApiPasswordDuringHeldRefresh();
    testEditDuringAccounting();
    testStrictTrafficBatches();
    testLossAndOrdering();
    testRecurringPullDoesNotStarvePush();
    testPeriodicAndExplicitPullCoalescing();
    testRequiredPullBeforeQueuedPush();
    testEmptyPushDoesNotDropPull();
    testRejectionsAndContinuity();
    testConcurrentAndSubsets();
    testBatchConstructionRefusal();
    userTestRuntimeCleanup();
    networkloggerDestroy();
    return 0;
}
