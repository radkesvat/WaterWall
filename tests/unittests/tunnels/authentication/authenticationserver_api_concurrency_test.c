/* CTest: waterwall.authenticationserver_api_concurrency_unit
 * Real construction/rollback, descriptor metadata, barrier-held query locks,
 * alternate calling worker, and owned reads concurrent with actual server
 * configuration/usage handlers. The fixture owns its one normal protocol line;
 * API operations receive buffers only. No host network or timing oracle. */
#include "AuthenticationServer/api.h"
#include "api/dispatcher.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "loggers/network_logger.h"
#include "modules/push_user_stats/push_user_stats.h"
#include "modules/update_user/update_user.h"
#include "wthread.h"

static bool      refuse_random, refuse_registration;
static unsigned  registrations, unregisters;
static tunnel_t *unregistered;

bool __real_secureRandomBytes(void *, size_t);
bool __wrap_secureRandomBytes(void *, size_t);
bool __wrap_secureRandomBytes(void *bytes, size_t size)
{
    if (refuse_random && size == 16)
    {
        refuse_random = false;
        return false;
    }
    return __real_secureRandomBytes(bytes, size);
}

bool __real_nodeApiRegister(tunnel_t *, const node_api_operation_t *, size_t);
bool __wrap_nodeApiRegister(tunnel_t *, const node_api_operation_t *, size_t);
bool __wrap_nodeApiRegister(tunnel_t *t, const node_api_operation_t *operations, size_t count)
{
    ++registrations;
    twfRequire(count == 4, "AuthenticationServer did not register exactly four operations");
    bool                     seen[4] = {false};
    static const char *const names[] = {"status", "get-user", "list-users", "update-user"};
    for (size_t i = 0; i < count; ++i)
    {
        twfRequire(operations[i].read_only == (strcmp(operations[i].name, "update-user") != 0) &&
                       operations[i].handler != NULL && operations[i].execution == kNodeApiCallingWorker &&
                       operations[i].response_encoding == kNodeApiEncodingUtf8 &&
                       strcmp(operations[i].request_content_type, "application/json") == 0 &&
                       strcmp(operations[i].response_content_type, "application/json") == 0,
                   "registered operation metadata mismatch");
        size_t match = 0;
        while (match < 4 && strcmp(operations[i].name, names[match]) != 0)
            ++match;
        twfRequire(match < 4 && ! seen[match], "unexpected or duplicate operation registration");
        seen[match] = true;
    }
    if (refuse_registration)
    {
        refuse_registration = false;
        return false;
    }
    return __real_nodeApiRegister(t, operations, count);
}

void __real_nodeApiUnregister(tunnel_t *);
void __wrap_nodeApiUnregister(tunnel_t *);
void __wrap_nodeApiUnregister(tunnel_t *t)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    size_t                         count;
    twfRequire(usersTryCount(&ts->store.users, 0, &count) == kUserPublicOk && ts->database_loaded,
               "API unregister happened after reachable storage reclamation");
    ++unregisters;
    unregistered = t;
    __real_nodeApiUnregister(t);
}

static api_result_t query(tunnel_t *t, const char *operation)
{
    const node_api_operation_t *descriptor = nodeApiFind(t, operation);
    twfRequire(descriptor != NULL, "query operation was not registered");
    const char    *body    = strcmp(operation, "get-user") == 0 ? "{\"id\":\"42\"}" : "{}";
    buffer_pool_t *pool    = getCurrentEventWorkerBufferPool();
    sbuf_t        *message = bufferpoolGetSmallBuffer(pool);
    sbufSetLength(message, (uint32_t) strlen(body));
    memoryCopy(sbufGetMutablePtr(message), body, strlen(body));
    node_api_call_context_t context = {.operation                = operation,
                                       .principal                = "test",
                                       .deadline_ms              = nodeApiNowMs() + 10000,
                                       .max_response_body_size   = 256U * 1024U,
                                       .working_memory_allowance = 1024U * 1024U};
    return descriptor->handler(t, message, &context);
}

static void requireQuery(tunnel_t *t, const char *operation, const char *error)
{
    api_result_t result = query(t, operation);
    twfRequire(result.buffer != NULL && result.result_code == (error == NULL ? kApiResultOk : kApiResultError),
               "query result code mismatch");
    cJSON *json = cJSON_ParseWithLength((const char *) sbufGetRawPtr(result.buffer), sbufGetLength(result.buffer));
    twfRequire(json != NULL, "query result was not JSON");
    if (error != NULL)
    {
        const cJSON *code = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(json, "error"), "code");
        twfRequire(cJSON_IsString(code) && strcmp(code->valuestring, error) == 0, "query error mismatch");
    }
    cJSON_Delete(json);
    bufferpoolReuseBuffer(getCurrentEventWorkerBufferPool(), result.buffer);
    twfRequireNoLeakedBuffers();
}

typedef struct writer_lock_s
{
    wrwlock_t  *lock;
    wsem_t      acquired, release;
    atomic_bool held;
} writer_lock_t;

static WTHREAD_ROUTINE(holdQueryLock)
{
    writer_lock_t *holder = userdata;
    rwlockWriteLock(holder->lock);
    atomic_store(&holder->held, true);
    semaphorePost(&holder->acquired);
    twfRequire(semaphoreWait(&holder->release), "lock holder release failed");
    atomic_store(&holder->held, false);
    rwlockWriteUnlock(holder->lock);
    return 0;
}

static void testBusy(tunnel_t *t)
{
    authenticationserver_tstate_t *ts   = tunnelGetState(t);
    user_t                        *user = usersLookupByIdentifier(&ts->store.users, 42);
    /* Deliberate test seams for the exact locks that a query must never wait on. */
    wrwlock_t *locks[] = {&ts->state_lock, &ts->store.users.lock, &user->lock, &user->stats_lock};
    for (size_t i = 0; i < sizeof(locks) / sizeof(locks[0]); ++i)
    {
        writer_lock_t holder = {.lock = locks[i]};
        atomic_init(&holder.held, false);
        semaphoreInit(&holder.acquired, 0);
        semaphoreInit(&holder.release, 0);
        wthread_t thread;
        twfRequire(threadCreate(&thread, holdQueryLock, &holder) == kWThreadErrorNone, "lock holder creation failed");
        twfRequire(semaphoreWait(&holder.acquired), "lock holder acquisition failed");
        requireQuery(t, "status", i < 2 ? "busy" : NULL);
        requireQuery(t, "get-user", "busy");
        requireQuery(t, "list-users", "busy");
        twfRequire(atomic_load(&holder.held), "query waited for lock holder release");
        semaphorePost(&holder.release);
        twfRequire(threadJoin(thread) == 0, "lock holder join failed");
        semaphoreDestroy(&holder.release);
        semaphoreDestroy(&holder.acquired);
        requireQuery(t, "status", NULL);
        requireQuery(t, "get-user", NULL);
        requireQuery(t, "list-users", NULL);
    }
}

static void testCallingWorker(tunnel_t *server, twf_worker_env_t *env)
{
    buffer_pool_t *second = bufferpoolCreate(env->large_master,
                                             env->medium_master,
                                             env->small_master,
                                             4,
                                             8192,
                                             MEDIUM_BUFFER_SIZE_RAM_HIGH,
                                             kTwfDefaultSmallBufferSize,
                                             8192,
                                             8192);
    twfRequire(second != NULL, "second worker pool creation failed");
    bufferpoolUpdateAllocationPaddings(second, 0, 0, 0, 0);
    wloop_t *second_loop = wloopCreate(WLOOP_FLAG_AUTO_FREE, second, 1);
    twfRequire(second_loop != NULL, "second event loop creation failed");
    buffer_pool_t *pools[] = {env->pool, second};
    wloop_t       *loops[] = {env->loop, second_loop};
    worker_t workers[] = {env->worker, {.wid = 1, .buffer_pool = second, .loop = second_loop, .has_event_loop = true}};
    GSTATE.workers_count         = 2;
    GSTATE.workers               = workers;
    GSTATE.shortcut_buffer_pools = pools;
    GSTATE.shortcut_loops        = loops;
    testWorkerBindWID(1);
    requireQuery(server, "status", NULL);
    requireQuery(server, "get-user", NULL);
    requireQuery(server, "list-users", NULL);
    twfRequire(g_twf_buffers.last_recycle_pool == second, "API borrowed another worker's buffer pool");
    testWorkerBindWID(0);
    GSTATE.workers_count         = 1;
    GSTATE.workers               = &env->worker;
    GSTATE.shortcut_buffer_pools = env->pool_shortcut;
    GSTATE.shortcut_loops        = env->loop_shortcut;
    wloopDestroy(&second_loop);
    bufferpoolDestroy(second);
}

typedef struct reader_s
{
    tunnel_t   *server;
    wsem_t      ready;
    atomic_bool stop;
    atomic_uint successes;
} reader_t;

static WTHREAD_ROUTINE(readOwnedViews)
{
    reader_t *reader = userdata;
    bool      ready  = false;
    do
    {
        authenticationserver_user_view_t view;
        const char *error = authenticationserverCopyUserView(reader->server, 42, 1024U * 1024U, 0, &view);
        if (error == NULL)
        {
            twfRequire(view.config_revision == view.user.gid + 1 && view.stats_revision == view.user.usage.u + 1 &&
                           view.user.usage.d == view.user.usage.u * 2 && strcmp(view.user.name, "Visible account") == 0,
                       "owned view mixed a configuration/usage transaction");
            atomic_fetch_add(&reader->successes, 1);
            if (! ready)
            {
                ready = true;
                semaphorePost(&reader->ready);
            }
        }
        else
            twfRequire(strcmp(error, "busy") == 0 && view.user.name == NULL,
                       "concurrent read refused without cleaning owned detail");
        userPublicDetailDestroy(&view.user);
    } while (! atomic_load(&reader->stop));
    return 0;
}

static void requireProtocolOk(line_t *line, sbuf_t *response)
{
    twfRequire(response != NULL && sbufGetLength(response) >= kAuthenticationServerResponseHeaderSize &&
                   ((const uint8_t *) sbufGetRawPtr(response))[0] == kAuthenticationServerResponseTypeOk,
               "real configuration/usage operation failed");
    lineReuseBuffer(line, response);
}

static void testConcurrentTransactions(tunnel_t *server)
{
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    const char                    *error;
    rwlockWriteLock(&ts->state_lock);
    authenticationserver_session_t *session =
        authenticationserverSessionCreate(server, "edge", "producer-secret", NULL, &error);
    rwlockWriteUnlock(&ts->state_lock);
    twfRequire(session != NULL, "real authentication session setup failed");
    char epoch[65] = {0};
    memoryCopy(epoch, session->accounting_epoch, 64);
    reader_t reader = {.server = server};
    semaphoreInit(&reader.ready, 0);
    atomic_init(&reader.stop, false);
    atomic_init(&reader.successes, 0);
    wthread_t readers[2];
    for (size_t i = 0; i < 2; ++i)
        twfRequire(threadCreate(&readers[i], readOwnedViews, &reader) == kWThreadErrorNone,
                   "owned reader creation failed");
    /* Start mutation only after both readers proved that their first owned
     * snapshot succeeded. Busy reads after this barrier are ordinary contention. */
    for (size_t i = 0; i < 2; ++i)
        twfRequire(semaphoreWait(&reader.ready), "initial reader snapshot barrier failed");
    twf_line_pool_t lines;
    twfLinePoolSetup(&lines, 0, 2);
    line_t              *line          = twfLinePoolCreateLine(&lines); /* Fixture-owned normal line. */
    static const uint8_t correlation[] = {1, 2, 3, 4};
    for (unsigned i = 1; i <= 80; ++i)
    {
        char patch[100], batch[300];
        int  patch_length = snprintf(patch, sizeof(patch), "{\"id\":\"42\",\"gid\":\"%u\"}", i);
        rwlockWriteLock(&ts->state_lock);
        sbuf_t *response = authenticationserverUpdateUserHandle(
            correlation, server, line, session, (const uint8_t *) patch, (uint32_t) patch_length);
        rwlockWriteUnlock(&ts->state_lock);
        requireProtocolOk(line, response);
        int batch_length = snprintf(batch,
                                    sizeof(batch),
                                    "{\"epoch\":\"%s\",\"sequence\":\"%u\",\"users\":[{\"id\":\"42\",\"up\":\"1\","
                                    "\"down\":\"2\",\"first-usage-at-ms\":\"1\"}]}",
                                    epoch,
                                    i);
        rwlockWriteLock(&ts->state_lock);
        response = authenticationserverPushUserStatsHandle(
            correlation, server, line, session, (const uint8_t *) batch, (uint32_t) batch_length);
        rwlockWriteUnlock(&ts->state_lock);
        requireProtocolOk(line, response);
    }
    atomic_store(&reader.stop, true);
    for (size_t i = 0; i < 2; ++i)
        twfRequire(threadJoin(readers[i]) == 0, "owned reader join failed");
    semaphoreDestroy(&reader.ready);
    twfRequire(atomic_load(&reader.successes) != 0, "concurrent readers never acquired a snapshot");
    lineDestroy(line);
    twfLinePoolTeardown(&lines);
    requireQuery(server, "get-user", NULL);
}

static void unusedCompletion(void *context, uint64_t session, uint64_t request, const node_api_reply_t *reply)
{
    discard context;
    discard session;
    discard request;
    discard reply;
    twfRequire(false, "closed-admission operation completed");
}

int main(void)
{
    twfSetCase("authenticationserver API concurrency and lifecycle");
    twfRequire(createNetworkLogger(NULL, false) != NULL && wCryptoGlobalInit() == kWCryptoOk, "runtime setup failed");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 8192, 0);
    twfRequire(globalstateInitializeSecureRandom(), "secure random initialization failed");
    nodeApiRegistryInitialize();
    char directory[] = "/tmp/ww-auth-api-concurrency-XXXXXX";
    twfRequire(mkdtemp(directory) != NULL, "temporary directory creation failed");
    char primary[512], backup[520];
    snprintf(primary, sizeof(primary), "%s/users.json", directory);
    snprintf(backup, sizeof(backup), "%s.backup", primary);
    FILE             *file = fopen(primary, "wb");
    static const char initial[] =
        "{\"users\":[{\"id\":42,\"name\":\"Visible account\",\"password\":\"private-credential\"}]}";
    twfRequire(file != NULL && fwrite(initial, 1, sizeof(initial) - 1, file) == sizeof(initial) - 1 &&
                   fclose(file) == 0,
               "database seed failed");
    cJSON  *settings = cJSON_CreateObject();
    discard cJSON_AddStringToObject(settings, "db-path", primary);
    discard cJSON_AddNumberToObject(settings, "file-save-rate-ms", 60000);
    cJSON  *clients = cJSON_AddArrayToObject(settings, "auth-clients");
    cJSON  *client  = cJSON_CreateObject();
    discard cJSON_AddItemToArray(clients, client);
    discard cJSON_AddStringToObject(client, "name", "edge");
    discard cJSON_AddStringToObject(client, "secret", "producer-secret");
    discard cJSON_AddBoolToObject(client, "allow-user-write", true);
    discard cJSON_AddBoolToObject(client, "allow-stats-push", true);
    node_t  node = {.node_settings_json = settings};

    refuse_random = true;
    twfRequire(authenticationserverTunnelCreate(&node) == NULL && ! refuse_random && registrations == 0 &&
                   unregisters == 1,
               "random-source failure did not roll back constructor");
    twfRequire(! nodeApiHasRegistration(unregistered), "random failure left an API registration");
    refuse_registration = true;
    tunnel_t *refused   = authenticationserverTunnelCreate(&node);
    twfRequire(refused == NULL && registrations == 1 && unregisters == 2,
               "registration failure did not roll back constructor");
    twfRequire(! nodeApiHasRegistration(unregistered), "registration failure retained reachable descriptor");
    tunnel_t *server = authenticationserverTunnelCreate(&node);
    twfRequire(server != NULL && registrations == 2 && nodeApiHasRegistration(server),
               "real constructor registration failed");
    uint8_t identity[16];
    memoryCopy(identity, ((authenticationserver_tstate_t *) tunnelGetState(server))->api_instance_id, 16);
    testBusy(server);
    testCallingWorker(server, &env);
    testConcurrentTransactions(server);
    authenticationserverTunnelDestroy(server, wwLifecycleStartupRollback());
    twfRequire(unregisters == 3 && ! nodeApiHasRegistration(unregistered), "destruction retained API descriptors");
    server = authenticationserverTunnelCreate(&node);
    twfRequire(server != NULL &&
                   memcmp(identity, ((authenticationserver_tstate_t *) tunnelGetState(server))->api_instance_id, 16) !=
                       0,
               "recreated server reused cursor instance identity");
    nodeApiFreeze();
    nodeApiCloseAdmission();
    node_api_domain_t *domain = nodeApiDomainCreate(4U * 1024U * 1024U, 4, unusedCompletion, NULL);
    twfRequire(domain != NULL, "dispatch domain construction failed");
    twfRequire(nodeApiJobCreate(domain,
                                server,
                                nodeApiFind(server, "status"),
                                0,
                                1,
                                1,
                                nodeApiNowMs() + 1000,
                                "test",
                                "{}",
                                2,
                                4096,
                                1024U * 1024U) == NULL,
               "closed admission accepted a provider job");
    nodeApiDomainDestroy(domain);
    authenticationserverTunnelDestroy(server, wwLifecycleStartupRollback());
    nodeApiRegistryDestroy();
    cJSON_Delete(settings);
    globalstateDestroySecureRandom();
    twfWorkerEnvTeardown(&env);
    twfRequire(remove(primary) == 0 && remove(backup) == 0 && rmdir(directory) == 0,
               "temporary database cleanup failed");
    puts("authenticationserver_api_concurrency_test: all checks passed");
    return 0;
}
