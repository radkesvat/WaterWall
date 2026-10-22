/* CTest: waterwall.authenticationclient_progress_unit
 * Real worker queue, control lines, timers and parsing with a controlled clock. */
#include "AuthenticationClient/structure.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "fixtures/user_runtime.h"
#include "loggers/network_logger.h"
#include <pthread.h>

static uint32_t retry_random;
uint32_t        __wrap_fastRand32(void);
uint32_t        __wrap_fastRand32(void)
{
    return retry_random;
}

static atomic_ullong clock_us;
unsigned long long   __wrap_getHRTimeUs(void);
unsigned long long   __wrap_getHRTimeUs(void)
{
    return atomicLoadU64(&clock_us);
}
static twf_worker_env_t env;
static twf_line_pool_t  lines;
static master_pool_t   *messages;
static tunnel_t        *client, *transport;
static tunnel_chain_t  *chain;
static unsigned         inits, finishes, depth, maximum_depth, other_work;
static unsigned         sends, capacity_warnings;
static bool             fail_init, establish, finish_payload;
static uint32_t         last_id;
static uint8_t          last_type, reply_type;
static bool             inspect_authentication, refuse_serialization;
static const cJSON     *authentication_json;
static const char      *authentication_secret;
static char            *authentication_text;
static size_t           authentication_secret_length, authentication_text_length;
static unsigned         wiped_json_secrets, wiped_texts, forwarded_authentication;

/* Private send/rollback seams exercise capacity released before wire delivery. */
bool authenticationclientSendRequest(tunnel_t *t, uint8_t request_type, const uint8_t *request_data,
                                     uint32_t request_data_len);
void authenticationclientRemovePendingById(tunnel_t *t, uint32_t correlation_id);

char *__real_cJSON_PrintUnformatted(const cJSON *json);
char *__wrap_cJSON_PrintUnformatted(const cJSON *json);
char *__wrap_cJSON_PrintUnformatted(const cJSON *json)
{
    if (! inspect_authentication)
        return __real_cJSON_PrintUnformatted(json);
    const cJSON *secret = cJSON_GetObjectItemCaseSensitive(json, "secret");
    twfRequire(cJSON_IsString(secret) && secret->valuestring != NULL, "Authenticate JSON secret missing");
    authentication_json          = json;
    authentication_secret        = secret->valuestring;
    authentication_secret_length = strlen(secret->valuestring) + 1;
    authentication_text          = refuse_serialization ? NULL : __real_cJSON_PrintUnformatted(json);
    authentication_text_length   = authentication_text ? strlen(authentication_text) + 1 : 0;
    return authentication_text;
}

void __real_cJSON_Delete(cJSON *json);
void __wrap_cJSON_Delete(cJSON *json);
void __wrap_cJSON_Delete(cJSON *json)
{
    if (json != NULL && json == authentication_json)
    {
        for (size_t i = 0; i < authentication_secret_length; ++i)
            twfRequire(authentication_secret[i] == 0, "decoded Authenticate secret was destroyed without wiping");
        authentication_json   = NULL;
        authentication_secret = NULL;
        ++wiped_json_secrets;
    }
    __real_cJSON_Delete(json);
}

void __real_cJSON_free(void *ptr);
void __wrap_cJSON_free(void *ptr);
void __wrap_cJSON_free(void *ptr)
{
    if (ptr != NULL && ptr == authentication_text)
    {
        for (size_t i = 0; i < authentication_text_length; ++i)
            twfRequire(((const char *) ptr)[i] == 0, "serialized Authenticate was freed without wiping");
        authentication_text = NULL;
        ++wiped_texts;
    }
    __real_cJSON_free(ptr);
}

static void init(tunnel_t *t, line_t *l)
{
    ++inits;
    ++depth;
    maximum_depth = max(maximum_depth, depth);
    if (fail_init)
        tunnelPrevDownStreamFinish(t, l);
    else if (establish)
        tunnelPrevDownStreamEst(t, l);
    --depth;
}
static void finish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++finishes;
}
static void payload(tunnel_t *t, line_t *l, sbuf_t *b)
{
    ++sends;
    last_type = ((const uint8_t *) sbufGetRawPtr(b))[68];
    memoryCopy(&last_id, (const uint8_t *) sbufGetRawPtr(b) + 69, 4);
    last_id = ntohl(last_id);
    if (inspect_authentication)
    {
        const size_t length = sbufGetLength(b);
        twfRequire(length > 77 &&
                       ((const uint8_t *) sbufGetRawPtr(b))[68] == kAuthenticationClientRequestTypeAuthenticate,
                   "expected forwarded Authenticate frame");
        cJSON       *json   = cJSON_ParseWithLength((const char *) sbufGetRawPtr(b) + 77, length - 77);
        const cJSON *secret = cJSON_GetObjectItemCaseSensitive(json, "secret");
        twfRequire(cJSON_IsString(secret) && strcmp(secret->valuestring, "secret") == 0,
                   "local wiping changed the already-transferred Authenticate request");
        cJSON_Delete(json);
        ++forwarded_authentication;
    }
    lineReuseBuffer(l, b);
    if (finish_payload)
        tunnelPrevDownStreamFinish(t, l);
}
static void other(void *worker, void *a, void *b, void *c)
{
    discard worker;
    discard a;
    discard b;
    discard c;
    ++other_work;
}
static void pump(uint32_t advance_ms)
{
    atomicAddU64(&clock_us, (uint64_t) advance_ms * 1000);
    for (unsigned i = 0; i < 4; ++i)
        discard wloopProcessEvents(env.loop, 0);
}
static authenticationclient_tstate_t *setup(void)
{
    atomicStoreU64(&clock_us, 100000000);
    inits = finishes = depth = maximum_depth = other_work = 0;
    sends = capacity_warnings = 0;
    fail_init = establish = finish_payload = false;
    reply_type                             = kAuthenticationClientResponseTypePong;
    retry_random                           = 0;
    twfWorkerEnvSetup(&env, 8192, 0);
    messages = masterpoolCreateWithCapacity(16);
    workerMessagesInstallMasterPoolCallbacks(messages);
    GSTATE.masterpool_messages = messages;
    mutexInit(&env.worker.control_mutex);
    workerMessagesInit(&env.worker);
    twfRequire(workerMessagesOpenAdmission(&env.worker), "message admission failed");
    env.loop->status = WLOOP_STATUS_RUNNING;
    client           = tunnelCreate(NULL, sizeof(authenticationclient_tstate_t), sizeof(authenticationclient_lstate_t));
    transport        = tunnelCreate(NULL, 0, 0);
    twfRequire(client != NULL && transport != NULL, "tunnel creation failed");
    client->fnFinD        = authenticationclientTunnelDownStreamFinish;
    client->fnEstD        = authenticationclientTunnelDownStreamEst;
    client->fnPayloadD    = authenticationclientTunnelDownStreamPayload;
    transport->fnInitU    = init;
    transport->fnFinU     = finish;
    transport->fnPayloadU = payload;
    tunnelBind(client, transport);
    twfLinePoolSetup(&lines, client->lstate_size, 4);
    chain                             = memoryCalloc(1, sizeof(*chain) + sizeof(generic_pool_t *));
    chain->line_pools[0]              = lines.pools[0];
    client->chain                     = chain;
    authenticationclient_tstate_t *ts = tunnelGetState(client);
    mutexInit(&ts->control_mutex);
    rwlockinit(&ts->users_lock);
    ts->started               = true;
    ts->name                  = stringDuplicate("edge");
    ts->secret                = stringDuplicate("secret");
    ts->next_correlation_id   = 1;
    ts->max_pending_requests  = 64;
    ts->sync_max_users        = kAuthenticationDefaultSyncMaxUsers;
    ts->sync_max_bytes        = kAuthenticationDefaultSyncMaxBytes;
    ts->reconnect_interval_ms = 5000;
    ts->request_timeout_ms    = 100;
    return ts;
}
static void teardown(void)
{
    authenticationclient_tstate_t *ts = tunnelGetState(client);
    authenticationclientTunnelOnQuiesceRequest(client, wwLifecycleProcessShutdown());
    workerMessagesCloseAdmission(&env.worker);
    workerMessagesCleanupPending(&env.worker);
    twfRequire(! ts->reconnect_work_pending, "cancellation retained retry latch");
    authenticationclientTunnelOnWorkerQuiesce(client, 0, wwLifecycleProcessShutdown());
    authenticationclientTunnelOnWorkerStop(client, 0, wwLifecycleProcessShutdown());
    twfRequire(ts->control_line == NULL && ts->request_timer == NULL && ts->reconnect_timer == NULL &&
                   ts->progress_timer == NULL,
               "stop left control resources alive");
    memoryFree(ts->pending_requests);
    cJSON_free(ts->pending_batch);
    memoryFree(ts->name);
    memoryFree(ts->secret);
    mutexDestroy(&ts->control_mutex);
    rwlockDestroy(&ts->users_lock);
    tunnelDestroy(transport);
    tunnelDestroy(client);
    memoryFree(chain);
    twfLinePoolTeardown(&lines);
    workerMessagesDestroy(&env.worker);
    mutexDestroy(&env.worker.control_mutex);
    GSTATE.masterpool_messages = NULL;
    masterpoolDestroy(messages);
    twfWorkerEnvTeardown(&env);
}
static void reply(uint32_t body, uint32_t id, bool valid)
{
    authenticationclient_tstate_t *ts     = tunnelGetState(client);
    const uint32_t                 length = valid ? 29 : (body == 17 ? 21 : 4);
    sbuf_t                        *b      = bufferpoolGetBestFit(env.pool, length, 0);
    sbufSetLength(b, length);
    memoryZero(sbufGetMutablePtr(b), length);
    uint32_t network = htonl(body);
    memoryCopy(sbufGetMutablePtr(b), &network, 4);
    if (valid)
    {
        sbufGetMutablePtr(b)[20] = reply_type;
        network                  = htonl(id);
        memoryCopy(sbufGetMutablePtr(b) + 21, &network, 4);
    }
    tunnelDownStreamPayload(client, ts->control_line, b);
}
static void *foreignRetry(void *unused)
{
    discard unused;
    for (unsigned i = 0; i < 100; ++i)
        authenticationclientScheduleReconnect(client);
    return NULL;
}
static void testRetryProgress(void)
{
    authenticationclient_tstate_t *ts = setup();
    ts->reconnect_interval_ms         = 0;
    fail_init                         = true;
    authenticationclientOpenControlLine(client);
    twfRequire(inits == 1 && ts->reconnect_work_pending, "zero retry ran synchronously");
    twfRequire(sendWorkerMessageForceQueueWithCleanup(0, other, NULL, NULL, NULL, NULL) == kWorkerMessageSubmitAccepted,
               "unrelated work was refused");
    pump(0);
    twfRequire(inits > 1 && maximum_depth == 1 && other_work == 1, "zero retry starved work or recursed");
    teardown();

    ts = setup();
    pthread_t threads[4];
    for (unsigned i = 0; i < 4; ++i)
        twfRequire(pthread_create(&threads[i], NULL, foreignRetry, NULL) == 0, "thread creation failed");
    for (unsigned i = 0; i < 4; ++i)
        pthread_join(threads[i], NULL);
    twfRequire(ts->reconnect_work_pending && ts->reconnect_timer == NULL, "foreign retry touched timer state");
    pump(0);
    const uint64_t due = ts->reconnect_due_ms;
    for (unsigned i = 0; i < 4; ++i)
    {
        pump(1000);
        authenticationclientScheduleReconnect(client);
        twfRequire(ts->reconnect_due_ms == due && inits == 0, "repeated request moved retry deadline");
    }
    pump(1000);
    twfRequire(inits == 1, "original retry deadline did not make progress");
    teardown();

    ts = setup();
    twfRequire(pthread_create(&threads[0], NULL, foreignRetry, NULL) == 0, "cancellation thread creation failed");
    authenticationclientTunnelOnQuiesceRequest(client, wwLifecycleProcessShutdown());
    workerMessagesCloseAdmission(&env.worker);
    pthread_join(threads[0], NULL);
    teardown();
}
static void testDeadlinesAndMalformed(void)
{
    authenticationclient_tstate_t *ts = setup();
    establish                         = true;
    authenticationclientOpenControlLine(client);
    twfRequire(ts->request_timer != NULL && ts->pending_count == 1, "Authenticate has no independent deadline");
    pump(99);
    twfRequire(finishes == 0, "request expired early");
    pump(1);
    twfRequire(finishes == 1 && ts->control_line == NULL && ts->reconnect_timer != NULL,
               "Authenticate timeout needed optional jobs");
    teardown();

    ts = setup();
    authenticationclientOpenControlLine(client);
    ts->connected = ts->authenticated = true;
    /* Model an authenticated session whose required initial pull completed. */
    ts->pull_requested = ts->pull_required = false;
    twfRequire(authenticationclientSendPing(client), "first manual request failed");
    uint32_t first = last_id;
    pump(50);
    twfRequire(authenticationclientSendPing(client), "second manual request failed");
    reply(25, first, true);
    twfRequire(ts->pending_count == 1, "reply settled another request");
    pump(50);
    twfRequire(finishes == 0, "settled request retained its deadline");
    pump(50);
    twfRequire(finishes == 1, "manual request did not expire independently");
    teardown();

    ts = setup();
    authenticationclientOpenControlLine(client);
    ts->connected = ts->authenticated = true;
    ts->pull_requested = ts->pull_required = false;
    twfRequire(authenticationclientSendPing(client), "early request failed");
    pump(50);
    twfRequire(authenticationclientSendPing(client), "later request failed");
    pump(50);
    twfRequire(finishes == 1, "later request postponed an earlier deadline");
    teardown();

    ts                     = setup();
    ts->request_timeout_ms = 0;
    establish              = true;
    authenticationclientOpenControlLine(client);
    pump(200000);
    twfRequire(ts->request_timer == NULL && finishes == 0, "zero timeout did not disable watchdog");
    teardown();
    const uint32_t malformed[] = {3, kAuthenticationClientMaxResponsePayload + 17, 17};
    for (unsigned i = 0; i < 3; ++i)
    {
        ts = setup();
        authenticationclientOpenControlLine(client);
        reply(malformed[i], 0, false);
        twfRequire(finishes == 1 && ts->reconnect_timer != NULL, "malformed response closed without retry");
        pump(5000);
        twfRequire(inits == 2, "malformed response retry needed ping");
        teardown();
    }
}

static void testPausedProgress(void)
{
    authenticationclient_tstate_t *ts = setup();
    authenticationclientOpenControlLine(client);
    ts->connected = ts->authenticated = true;
    ts->pull_requested = ts->pull_required = true;
    authenticationclientScheduleSyncProgress(client);
    twfRequire(ts->progress_timer != NULL, "eligible synchronization did not schedule progress");
    authenticationclientTunnelDownStreamPause(client, ts->control_line);
    authenticationclientResumeSync(client);
    for (unsigned i = 0; i < 20; ++i)
    {
        pump(1);
        twfRequire(ts->progress_timer == NULL && ts->pending_count == 0,
                   "paused synchronization armed repeated progress work");
    }
    authenticationclientTunnelDownStreamResume(client, ts->control_line);
    twfRequire(ts->pull_in_flight && ts->pending_count == 1, "Resume did not continue remembered synchronization");
    teardown();
}

static void captureCapacityWarning(int level, const char *data, int length)
{
    discard level;
    discard length;
    if (strstr(data, "pending request table is full") != NULL)
        ++capacity_warnings;
}

static void testPendingCapacityProgress(void)
{
    for (unsigned mode = 0; mode < 4; ++mode)
    {
        authenticationclient_tstate_t *ts = setup();
        ts->max_pending_requests          = 1;
        ts->request_timeout_ms            = mode == 0 ? 0 : 100;
        authenticationclientOpenControlLine(client);
        ts->connected = ts->authenticated = true;
        ts->pull_requested = ts->pull_required = false;
        twfRequire(authenticationclientSendPing(client), "capacity Ping failed");
        const uint32_t ping     = last_id;
        logger_handler original = getNetworkLoggerHandle();
        loggerSetHandler(getNetworkLogger(), captureCapacityWarning);
        authenticationclientRequestPull(client);
        authenticationclientRequestPush(client);
        for (unsigned i = 0; i < 20; ++i)
        {
            authenticationclientResumeSync(client);
            authenticationclientScheduleSyncProgress(client);
            pump(1);
            twfRequire(sends == 1 && ts->pending_count == 1 && ts->progress_timer == NULL &&
                           ts->pending_batch == NULL && ts->pull_requested && ts->push_requested,
                       "full pending table sent, rebuilt a batch, lost demand or spun its progress timer");
        }
        loggerSetHandler(getNetworkLogger(), original);
        twfRequire(capacity_warnings == 0, "ordinary pending capacity pressure emitted a warning");
        wtimer_t *deadline = ts->request_timer;
        reply(25, ping + 1, true);
        twfRequire(sends == 1 && ts->pending_count == 1 && ts->progress_timer == NULL && ts->request_timer == deadline,
                   "stale Pong freed capacity or invented a wakeup");
        if (mode == 2)
        {
            reply_type = kAuthenticationClientResponseTypeSession;
            reply(25, ping, true);
            twfRequire(sends == 1 && ts->control_line == NULL &&
                           ts->last_failure == kAuthenticationClientFailureInvalidResponse,
                       "invalid matching response resumed queued work before semantic validation");
        }
        else if (mode == 3)
        {
            pump(80);
            twfRequire(sends == 1 && ts->control_line == NULL &&
                           ts->last_failure == kAuthenticationClientFailureTimeout,
                       "full pending table prevented the absolute request timeout");
        }
        else
        {
            finish_payload = mode == 1;
            reply(25, ping, true);
            twfRequire(sends == 2 && last_type == kAuthenticationClientRequestTypeGetUsersPage &&
                           (finish_payload ? ts->control_line == NULL : ts->pull_in_flight),
                       "matching Pong did not autonomously resume queued work or handle synchronous Finish");
        }
        teardown();
    }

    authenticationclient_tstate_t *ts = setup();
    ts->max_pending_requests          = 1;
    authenticationclientOpenControlLine(client);
    ts->connected = ts->authenticated = true;
    ts->pull_required                 = false;
    ts->pull_requested                = true;
    twfRequire(! authenticationclientSendRequest(
                   client, kAuthenticationClientRequestTypePing, NULL, kAuthenticationClientMaxRequestData + 1U) &&
                   ts->pending_count == 0 && ts->progress_timer != NULL && sends == 0,
               "local send rollback did not defer a capacity continuation");
    pump(1);
    twfRequire(sends == 1 && ts->pull_in_flight, "rollback continuation lost an explicit ordinary pull");
    teardown();

    ts = setup();
    authenticationclientOpenControlLine(client);
    ts->connected = ts->authenticated = true;
    ts->pull_required                 = false;
    ts->pull_requested                = true;
    authenticationclientRemovePendingById(client, 999);
    twfRequire(ts->progress_timer == NULL, "stale rollback correlation invented a continuation");
    authenticationclientScheduleSyncProgress(client);
    twfRequire(ts->progress_timer != NULL, "ordinary explicit pull was missing from runnable work");
    authenticationclientTunnelOnQuiesceRequest(client, wwLifecycleProcessShutdown());
    pump(1);
    twfRequire(sends == 0 && ts->progress_timer == NULL, "quiescence rearmed capacity continuation");
    teardown();
}

static char     diagnostic[1024];
static unsigned diagnostic_count;
static void     captureDiagnostic(int level, const char *data, int length)
{
    discard level;
    if (strstr(data, "AuthenticationClient: request ") == NULL)
        return;
    twfRequire(length >= 0 && (size_t) length < sizeof(diagnostic), "unbounded refusal diagnostic");
    memoryCopy(diagnostic, data, (size_t) length);
    diagnostic[length] = 0;
    ++diagnostic_count;
}

static void errorReply(const uint8_t *data, uint32_t length)
{
    authenticationclient_tstate_t *ts = tunnelGetState(client);
    sbuf_t                        *b  = bufferpoolGetBestFit(env.pool, 29 + length, 0);
    sbufSetLength(b, 29 + length);
    memoryZero(sbufGetMutablePtr(b), 29);
    uint32_t number = htonl(25 + length);
    memoryCopy(sbufGetMutablePtr(b), &number, 4);
    sbufGetMutablePtr(b)[20] = kAuthenticationClientResponseTypeError;
    number                   = htonl(last_id);
    memoryCopy(sbufGetMutablePtr(b) + 21, &number, 4);
    number = htonl(length);
    memoryCopy(sbufGetMutablePtr(b) + 25, &number, 4);
    memoryCopy(sbufGetMutablePtr(b) + 29, data, length);
    tunnelDownStreamPayload(client, ts->control_line, b);
}

static void testRefusalClassificationAndDiagnostics(void)
{
    static const char *errors[] = {"stats-push-not-allowed",
                                   "invalid-usage-batch",
                                   "usage-digest-failed",
                                   "unknown-error",
                                   "usage-replay-conflict",
                                   "usage-sequence-invalid",
                                   "accounting-continuity-lost",
                                   "authentication-required"};
    for (unsigned i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i)
    {
        authenticationclient_tstate_t *ts = setup();
        authenticationclientOpenControlLine(client);
        ts->connected = ts->authenticated = true;
        ts->pending_batch                 = stringDuplicate("retained-batch");
        ts->pending_batch_length          = (uint32_t) stringLength(ts->pending_batch);
        ts->accounting_epoch[0]           = 'a';
        ts->next_batch_sequence           = 7;
        twfRequire(authenticationclientSendPushUserStats(client), "classification push not sent");
        errorReply((const uint8_t *) errors[i], (uint32_t) stringLength(errors[i]));
        const bool terminal = i >= 4 && i <= 6;
        twfRequire(ts->continuity_error == terminal && ts->stats_push_refused == (i < 4) &&
                       ts->next_batch_sequence == 7 && strcmp(ts->pending_batch, "retained-batch") == 0 &&
                       (terminal ? ts->reconnect_timer == NULL : ts->reconnect_timer != NULL),
                   "error classification changed retained accounting or terminal behavior");
        if (i < 4)
            twfRequire(ts->last_failure == (i == 0 ? kAuthenticationClientFailureStatsPushDenied
                                                   : kAuthenticationClientFailureStatsPushRejected),
                       "nonterminal refusal has the wrong bounded status classification");
        teardown();
    }

    authenticationclient_tstate_t *ts = setup();
    authenticationclientOpenControlLine(client);
    ts->connected = ts->authenticated = true;
    ts->pull_requested = ts->pull_required = false;
    twfRequire(authenticationclientSendPing(client), "diagnostic request failed");
    uint8_t bytes[160];
    memorySet(bytes, 1, sizeof(bytes));
    const uint8_t special[] = {'\r', '\n', 0x1B, '\t', 0, '\\', 0xC0, 0xFF, 0x7F, 'A'};
    memoryCopy(bytes, special, sizeof(special));
    logger_handler original = getNetworkLoggerHandle();
    loggerSetHandler(getNetworkLogger(), captureDiagnostic);
    diagnostic_count = 0;
    errorReply(bytes, sizeof(bytes));
    loggerSetHandler(getNetworkLogger(), original);
    twfRequire(diagnostic_count == 1 && strlen(diagnostic) < 650 &&
                   strstr(diagnostic, "\\x0D\\x0A\\x1B\\x09\\x00\\\\\\xC0\\xFF\\x7FA") != NULL &&
                   strstr(diagnostic, "...[truncated]") != NULL,
               "remote diagnostic did not escape every byte or mark truncation");
    for (size_t i = 0; diagnostic[i] != '\0'; ++i)
        twfRequire((diagnostic[i] >= 0x20 && diagnostic[i] <= 0x7E) ||
                       (diagnostic[i] == '\n' && diagnostic[i + 1] == '\0'),
                   "remote error injected a physical line or terminal control");
    twfRequire(! ts->continuity_error && ts->last_failure == kAuthenticationClientFailureRemoteError,
               "diagnostic escaping changed protocol classification");
    teardown();
}
static void testOwnedAuthenticateCleanup(void)
{
    for (unsigned path = 0; path < 3; ++path)
    {
        authenticationclient_tstate_t *ts = setup();
        wiped_json_secrets = wiped_texts = forwarded_authentication = 0;
        inspect_authentication                                      = true;
        refuse_serialization                                        = path == 2;
        if (path == 0)
        {
            establish = true;
            authenticationclientOpenControlLine(client);
            twfRequire(ts->control_line != NULL, "Authenticate transport open");
        }
        else
            twfRequire(! authenticationclientSendAuthenticate(client), "refused Authenticate unexpectedly sent");
        twfRequire(wiped_json_secrets == 1 && wiped_texts == (path == 2 ? 0U : 1U) &&
                       forwarded_authentication == (path == 0 ? 1U : 0U) && authentication_json == NULL &&
                       authentication_text == NULL,
                   "Authenticate success/refusal/serialization failure did not settle owned sensitive copies");
        inspect_authentication = refuse_serialization = false;
        teardown();
    }
}

static void testRepeatedSyncBackoff(void)
{
    authenticationclient_tstate_t *ts = setup();
    ts->reconnect_interval_ms         = 0;
    const uint64_t now                = getHRTimeUs() / 1000;
    authenticationclientRecordFailure(client, kAuthenticationClientFailureTransportClosed, 0);
    twfRequire(ts->sync_retry_streak == 1 && ts->sync_retry_not_before_ms == now,
               "first zero retry lost its queue semantics");
    uint64_t delay = 1000;
    for (unsigned n = 2; n <= 12; ++n)
    {
        retry_random = (uint32_t) (delay / 4);
        authenticationclientRecordFailure(
            client, kAuthenticationClientFailureInvalidResponse, kAuthenticationClientRequestTypeGetUsersPage);
        twfRequire(ts->sync_retry_streak == n && ts->sync_retry_not_before_ms == now + delay + delay / 4,
                   "retry exponential delay/cap/jitter bound changed");
        const uint64_t due = ts->sync_retry_not_before_ms;
        authenticationclientOpenControlLine(client);
        authenticationclientResumeSync(client);
        authenticationclientScheduleReconnect(client);
        twfRequire(inits == 0 && ts->pending_count == 0 && ts->sync_retry_not_before_ms == due &&
                       ts->progress_timer == NULL && ts->reconnect_timer != NULL,
                   "direct work bypassed or extended failed-sync backoff");
        delay = min(delay * 2, UINT64_C(60000));
    }
    authenticationclient_status_t snapshot;
    authenticationclientStatusSnapshot(client, false, 0, 0, &snapshot);
    twfRequire(snapshot.sync_retry_streak == 12 && snapshot.sync_retry_remaining_ms == 75000 &&
                   snapshot.sync_retry_failure == kAuthenticationClientFailureInvalidResponse,
               "status lost fixed retry facts");
    /* A published earlier timer cannot open the line ahead of the effective
     * deadline; it reschedules rather than spinning a short progress timer. */
    pump(1000);
    twfRequire(inits == 0 && ts->reconnect_timer != NULL, "obsolete retry bypassed later failure deadline");
    pump(74000);
    twfRequire(inits == 1, "backoff did not provide its own wakeup with optional jobs disabled");
    teardown();
}

int main(void)
{
    twfSetCase("authenticationclient request and reconnect progress");
    twfRequire(createNetworkLogger(NULL, false) != NULL, "logger setup failed");
    twfRequire(userTestRuntimeInitialize(), "user runtime initialization failed");
    testRepeatedSyncBackoff();
    testRetryProgress();
    testDeadlinesAndMalformed();
    testPausedProgress();
    testPendingCapacityProgress();
    testRefusalClassificationAndDiagnostics();
    testOwnedAuthenticateCleanup();
    userTestRuntimeCleanup();
    networkloggerDestroy();
    return 0;
}
