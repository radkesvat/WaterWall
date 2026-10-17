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
static bool                       hold_pull, hold_push;
static unsigned                   last_response;
static int                        raw_response[2];
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
    hold_pull = hold_push = false;
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

static void rawBatch(line_t *l, const uint8_t token[64], const char *text)
{
    const uint32_t length  = (uint32_t) stringLength(text);
    sbuf_t        *message = bufferpoolGetBestFit(lineGetBufferPool(l), 77 + length, 0);
    sbufSetLength(message, 77 + length);
    uint8_t *bytes = sbufGetMutablePtr(message);
    memoryZero(bytes, 77);
    uint32_t number = htonl(73 + length);
    memoryCopy(bytes, &number, 4);
    memoryCopy(bytes + 4, token, 64);
    bytes[68] = kAuthenticationClientRequestTypePushUserStats;
    number    = htonl(0xFFFF);
    memoryCopy(bytes + 69, &number, 4);
    number = htonl(length);
    memoryCopy(bytes + 73, &number, 4);
    memoryCopy(bytes + 77, text, length);
    tunnelUpStreamPayload(server, l, message);
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
    testLossAndOrdering();
    testRejectionsAndContinuity();
    testConcurrentAndSubsets();
    testBatchConstructionRefusal();
    wCryptoGlobalCleanup();
    globalstateDestroySecureRandom();
    networkloggerDestroy();
    return 0;
}
