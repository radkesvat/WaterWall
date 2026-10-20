/* CTest: waterwall.authenticationclient_progress_unit
 * Real worker queue, control lines, timers and parsing with a controlled clock. */
#include "AuthenticationClient/structure.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "loggers/network_logger.h"
#include <pthread.h>

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
static bool             fail_init, establish;
static uint32_t         last_id;

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
    discard t;
    memoryCopy(&last_id, (const uint8_t *) sbufGetRawPtr(b) + 69, 4);
    last_id = ntohl(last_id);
    lineReuseBuffer(l, b);
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
    fail_init = establish = false;
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
        sbufGetMutablePtr(b)[20] = kAuthenticationClientResponseTypePong;
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
int main(void)
{
    twfSetCase("authenticationclient request and reconnect progress");
    twfRequire(createNetworkLogger(NULL, false) != NULL, "logger setup failed");
    testRetryProgress();
    testDeadlinesAndMalformed();
    testPausedProgress();
    testRefusalClassificationAndDiagnostics();
    networkloggerDestroy();
    return 0;
}
