/* CTest: waterwall.authenticationserver_api_concurrency_unit
 * Real construction/rollback, descriptor metadata, barrier-held query locks,
 * alternate calling worker, owned reads concurrent with configuration/usage,
 * and conditional password/configuration/creation races with indexed readers.
 * The fixture owns its one normal protocol line;
 * API operations receive buffers only. No host network or timing oracle. */
#include "AuthenticationServer/api.h"
#include "AuthenticationServer/config_create.h"
#include "AuthenticationServer/config_update.h"
#include "AuthenticationServer/password_change.h"
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
    twfRequire(count == 6, "AuthenticationServer did not register exactly six operations");
    bool                     seen[6] = {false};
    static const char *const names[] = {
        "status", "get-user", "list-users", "update-user", "create-user", "change-user-password"};
    for (size_t i = 0; i < count; ++i)
    {
        twfRequire(operations[i].read_only == (strcmp(operations[i].name, "update-user") != 0 &&
                                               strcmp(operations[i].name, "create-user") != 0 &&
                                               strcmp(operations[i].name, "change-user-password") != 0) &&
                       operations[i].handler != NULL && operations[i].execution == kNodeApiCallingWorker &&
                       operations[i].response_encoding == kNodeApiEncodingUtf8 &&
                       strcmp(operations[i].request_content_type, "application/json") == 0 &&
                       strcmp(operations[i].response_content_type, "application/json") == 0,
                   "registered operation metadata mismatch");
        size_t match = 0;
        while (match < 6 && strcmp(operations[i].name, names[match]) != 0)
            ++match;
        twfRequire(match < 6 && ! seen[match], "unexpected or duplicate operation registration");
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
    buffer_pool_t *pool    = getCurrentWorkerBufferPool();
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
    bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), result.buffer);
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
    worker_t       workers[]     = {env->worker, {.wid = 1, .buffer_pool = second, .loop = second_loop}};
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

typedef enum mixed_write_kind_e
{
    kMixedPassword,
    kMixedConfig,
    kMixedCreate
} mixed_write_kind_t;

typedef struct mixed_writer_s
{
    tunnel_t                               *server;
    mixed_write_kind_t                      kind;
    authenticationserver_password_request_t password;
    authenticationserver_update_request_t   config;
    authenticationserver_create_request_t   creation;
    node_api_call_context_t                 context;
    sbuf_t                                 *ack;
    wsem_t                                 *ready, *start;
    const char                             *error;
} mixed_writer_t;

static void executeMixedWrite(mixed_writer_t *writer)
{
    switch (writer->kind)
    {
    case kMixedPassword:
        writer->error = authenticationserverApplyConditionalPasswordChange(
            writer->server, &writer->password, &writer->context, writer->ack, 1024U * 1024U);
        break;
    case kMixedConfig:
        writer->error = authenticationserverApplyConditionalUpdate(
            writer->server, &writer->config, &writer->context, writer->ack, 1024U * 1024U);
        break;
    case kMixedCreate:
        writer->error = authenticationserverApplyCreate(
            writer->server, &writer->creation, &writer->context, writer->ack, 1024U * 1024U);
        break;
    }
}

static WTHREAD_ROUTINE(mixedConditionalWriter)
{
    mixed_writer_t *writer = userdata;
    semaphorePost(writer->ready);
    twfRequire(semaphoreWait(writer->start), "mixed writer start failed");
    executeMixedWrite(writer);
    return 0;
}

static void prepareMixedWrite(mixed_writer_t *writer, tunnel_t *server, mixed_write_kind_t kind, const char *body)
{
    *writer         = (mixed_writer_t) {.server = server, .kind = kind};
    writer->context = (node_api_call_context_t) {
        .principal = "password-admin", .working_memory_allowance = 4U * 1024U * 1024U, .max_response_body_size = 4096};
    buffer_pool_t *pool    = getCurrentWorkerBufferPool();
    const size_t   length  = strlen(body);
    sbuf_t        *message = bufferpoolGetBestFit(pool, (uint32_t) length, 0);
    memoryCopy(sbufGetMutablePtr(message), body, length);
    sbufSetLength(message, (uint32_t) length);
    const char *error;
    switch (kind)
    {
    case kMixedPassword:
        error = authenticationserverParsePasswordChange(message, &writer->context, &writer->password);
        break;
    case kMixedConfig:
        error = authenticationserverParseUpdate(message, &writer->context, &writer->config);
        break;
    case kMixedCreate:
        error = authenticationserverParseCreate(message, &writer->context, &writer->creation);
        break;
    default:
        error = "invalid fixture kind";
    }
    twfRequire(error == NULL, "mixed writer preparation failed");
    writer->ack = bufferpoolGetBestFit(pool, 256, 0);
}

static void destroyMixedWrite(mixed_writer_t *writer)
{
    usersFreePreparedPasswordChange(writer->password.password);
    usersFreePreparedConfigPatch(writer->config.patch);
    usersFreePreparedNewUser(writer->creation.candidate);
    bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), writer->ack);
}

typedef struct indexed_reader_s
{
    users_t    *users;
    user_t     *target;
    wsem_t      ready;
    atomic_bool stop;
    atomic_uint observations;
} indexed_reader_t;

static WTHREAD_ROUTINE(readCredentialIndexes)
{
    indexed_reader_t *reader = userdata;
    do
    {
        /* Validation pins collection and individual config locks, so it sees
         * either complete credential generation, including every index. */
        twfRequire(usersValidate(reader->users) && usersLookupByIdentifier(reader->users, 42) == reader->target,
                   "password transaction exposed inconsistent indexes or moved account");
        if (atomic_fetch_add(&reader->observations, 1) == 0)
            semaphorePost(&reader->ready);
    } while (! atomic_load(&reader->stop));
    return 0;
}

static void mixedCredentialTransactions(tunnel_t *server)
{
    authenticationserver_tstate_t *ts     = tunnelGetState(server);
    user_t                        *stable = usersLookupByIdentifier(&ts->store.users, 42);
    for (unsigned scenario = 0; scenario < 4; ++scenario)
    {
        char token[49], rotate_body[512], other_body[512], password[80];
        authenticationserverEditTokenFormat(ts->api_instance_id, ts->store.config_revision, token);
        snprintf(password, sizeof(password), "mixed-password-%u", scenario);
        snprintf(rotate_body,
                 sizeof(rotate_body),
                 "{\"id\":\"42\",\"if_match\":\"%s\",\"password\":\"%s\"}",
                 token,
                 password);
        mixed_write_kind_t other_kind;
        if (scenario == 0)
        {
            other_kind = kMixedPassword;
            snprintf(other_body,
                     sizeof(other_body),
                     "{\"id\":\"42\",\"if_match\":\"%s\",\"password\":\"mixed-other-password\"}",
                     token);
        }
        else if (scenario == 1)
        {
            other_kind = kMixedConfig;
            snprintf(other_body,
                     sizeof(other_body),
                     "{\"id\":\"42\",\"if_match\":\"%s\",\"patch\":{\"gid\":\"900\"}}",
                     token);
        }
        else
        {
            other_kind = kMixedCreate;
            snprintf(other_body,
                     sizeof(other_body),
                     "{\"id\":\"%u\",\"password\":\"%s\"}",
                     200U + scenario,
                     scenario == 3 ? password : "mixed-independent-account");
        }
        mixed_writer_t writers[2];
        prepareMixedWrite(&writers[0], server, kMixedPassword, rotate_body);
        prepareMixedWrite(&writers[1], server, other_kind, other_body);
        wsem_t ready, start;
        semaphoreInit(&ready, 0);
        semaphoreInit(&start, 0);
        indexed_reader_t reader = {.users = &ts->store.users, .target = stable};
        atomic_init(&reader.stop, false);
        atomic_init(&reader.observations, 0);
        semaphoreInit(&reader.ready, 0);
        wthread_t reader_thread, threads[2];
        twfRequire(threadCreate(&reader_thread, readCredentialIndexes, &reader) == kWThreadErrorNone &&
                       semaphoreWait(&reader.ready),
                   "indexed reader barrier failed");
        const uint64_t revision = ts->store.config_revision;
        for (size_t i = 0; i < 2; ++i)
        {
            writers[i].ready = &ready;
            writers[i].start = &start;
            twfRequire(threadCreate(&threads[i], mixedConditionalWriter, &writers[i]) == kWThreadErrorNone,
                       "mixed writer creation failed");
        }
        twfRequire(semaphoreWait(&ready) && semaphoreWait(&ready), "mixed writer readiness failed");
        semaphorePost(&start);
        semaphorePost(&start);
        for (size_t i = 0; i < 2; ++i)
            twfRequire(threadJoin(threads[i]) == 0, "mixed writer join failed");
        atomic_store(&reader.stop, true);
        twfRequire(threadJoin(reader_thread) == 0 && atomic_load(&reader.observations) != 0,
                   "indexed reader failed to observe table");
        unsigned commits = 0;
        for (size_t i = 0; i < 2; ++i)
        {
            if (writers[i].error == NULL)
                ++commits;
            else
                twfRequire(strcmp(writers[i].error, "busy") == 0 || strcmp(writers[i].error, "conflict") == 0 ||
                               (scenario == 3 && strcmp(writers[i].error, "credentials_exist") == 0),
                           "unexpected mixed writer refusal");
        }
        twfRequire(commits <= (scenario == 2 ? 2U : 1U) && ts->store.config_revision == revision + commits,
                   "competing writes bypassed token or credential uniqueness");
        /* Indexed readers can legitimately make both try-lock writers busy.
         * Settle one actual mutation after the readers have joined, then prove
         * the old token cannot cause a second conditional commit. */
        if (commits == 0)
        {
            executeMixedWrite(&writers[0]);
            twfRequire(writers[0].error == NULL, "uncontended password mutation failed");
            ++commits;
        }
        {
            mixed_writer_t stale;
            prepareMixedWrite(&stale, server, kMixedPassword, rotate_body);
            executeMixedWrite(&stale);
            twfRequire(stale.error && strcmp(stale.error, "conflict") == 0,
                       "old token replayed a committed password change");
            destroyMixedWrite(&stale);
        }
        if (scenario == 2 && writers[1].error != NULL)
        {
            executeMixedWrite(&writers[1]);
            twfRequire(writers[1].error == NULL, "independent creation after rotation was refused");
            ++commits;
        }
        if (scenario == 3)
        {
            user_t *owner = usersLookupByPassword(&ts->store.users, password);
            twfRequire(owner != NULL && (owner == stable || owner->id == 203) &&
                           (usersLookupByIdentifier(&ts->store.users, 203) == NULL || owner->id == 203),
                       "competing credential claim produced two identities");
        }
        twfRequire(ts->store.config_revision == revision + commits && usersValidate(&ts->store.users),
                   "mixed transaction revision/index mismatch");
        destroyMixedWrite(&writers[0]);
        destroyMixedWrite(&writers[1]);
        semaphoreDestroy(&reader.ready);
        semaphoreDestroy(&start);
        semaphoreDestroy(&ready);
    }
    /* A create committed first invalidates a pre-existing rotation token. */
    char token[49], body[512];
    authenticationserverEditTokenFormat(ts->api_instance_id, ts->store.config_revision, token);
    snprintf(body, sizeof(body), "{\"id\":\"42\",\"if_match\":\"%s\",\"password\":\"stale-after-create\"}", token);
    mixed_writer_t pending, creator;
    prepareMixedWrite(&pending, server, kMixedPassword, body);
    prepareMixedWrite(&creator, server, kMixedCreate, "{\"id\":\"204\",\"password\":\"create-invalidates-rotation\"}");
    executeMixedWrite(&creator);
    executeMixedWrite(&pending);
    twfRequire(creator.error == NULL && pending.error != NULL && strcmp(pending.error, "conflict") == 0 &&
                   usersLookupByPassword(&ts->store.users, "stale-after-create") == NULL &&
                   usersLookupByIdentifier(&ts->store.users, 42) == stable && usersValidate(&ts->store.users),
               "creation did not invalidate the prior rotation precondition");
    destroyMixedWrite(&pending);
    destroyMixedWrite(&creator);
    twfRequireNoLeakedBuffers();
}

static void requireRecoveryFilesUnchanged(const char *primary, const char *backup, const char *expected_primary,
                                          const char *expected_backup)
{
    char *actual_primary = readFile(primary);
    char *actual_backup  = readFile(backup);
    twfRequire(actual_primary != NULL && actual_backup != NULL && strcmp(actual_primary, expected_primary) == 0 &&
                   strcmp(actual_backup, expected_backup) == 0,
               "startup rollback modified primary or recovery database");
    memoryFree(actual_primary);
    memoryFree(actual_backup);
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
    static const char recovery[] = "{\"users\":[{\"id\":41,\"password\":\"distinct-recovery\"}]}";
    file                         = fopen(backup, "wb");
    twfRequire(file != NULL && fwrite(recovery, 1, sizeof(recovery) - 1, file) == sizeof(recovery) - 1 &&
                   fclose(file) == 0,
               "recovery seed failed");
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
    requireRecoveryFilesUnchanged(primary, backup, initial, recovery);
    refuse_registration = true;
    tunnel_t *refused   = authenticationserverTunnelCreate(&node);
    twfRequire(refused == NULL && registrations == 1 && unregisters == 2,
               "registration failure did not roll back constructor");
    twfRequire(! nodeApiHasRegistration(unregistered), "registration failure retained reachable descriptor");
    requireRecoveryFilesUnchanged(primary, backup, initial, recovery);
    tunnel_t *server = authenticationserverTunnelCreate(&node);
    twfRequire(server != NULL && registrations == 2 && nodeApiHasRegistration(server),
               "real constructor registration failed");
    uint8_t identity[16];
    memoryCopy(identity, ((authenticationserver_tstate_t *) tunnelGetState(server))->api_instance_id, 16);
    testBusy(server);
    testCallingWorker(server, &env);
    testConcurrentTransactions(server);
    mixedCredentialTransactions(server);
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
                                NULL,
                                NULL,
                                "{}",
                                2,
                                4096,
                                1024U * 1024U) == NULL,
               "closed admission accepted a provider job");
    nodeApiDomainDestroy(domain);
    authenticationserver_tstate_t *final_state = tunnelGetState(server);
    cJSON                         *final_user  = cJSON_Parse("{\"id\":999,\"password\":\"normal-shutdown-persisted\"}");
    twfRequire(final_user != NULL &&
                   usersAddUserFromJsonChecked(&final_state->store.users, final_user) == kUsersAddResultOk,
               "normal shutdown mutation setup failed");
    cJSON_Delete(final_user);
    char *retained_recovery = readFile(backup);
    twfRequire(retained_recovery != NULL && remove(primary) == 0, "shutdown missing-primary setup failed");
    authenticationserverTunnelDestroy(server, wwLifecycleProcessShutdown());
    char *after_shutdown_recovery = readFile(backup);
    twfRequire(after_shutdown_recovery != NULL && strcmp(after_shutdown_recovery, retained_recovery) == 0,
               "final missing-primary save changed recovery backup");
    memoryFree(after_shutdown_recovery);
    memoryFree(retained_recovery);
    char *persisted = readFile(primary);
    twfRequire(persisted != NULL && strstr(persisted, "normal-shutdown-persisted") != NULL,
               "normal process shutdown did not persist runtime changes");
    memoryFree(persisted);
    nodeApiRegistryDestroy();
    cJSON_Delete(settings);
    globalstateDestroySecureRandom();
    twfWorkerEnvTeardown(&env);
    twfRequire(remove(primary) == 0 && remove(backup) == 0 && rmdir(directory) == 0,
               "temporary database cleanup failed");
    puts("authenticationserver_api_concurrency_test: all checks passed");
    return 0;
}
