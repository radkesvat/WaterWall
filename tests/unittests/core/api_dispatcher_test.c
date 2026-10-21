/* Detached jobs: force-queue same-worker, worker 1 -> 0 -> 1, opaque binary
 * request/result, refusal cleanup, queued/running abandonment, deadline and
 * synchronized reservations. Forked shutdown cases retain queued/running work
 * through both worker-stop orders. Real worker queues/pools; no lines or sockets.
 * CTest: waterwall.api_dispatcher_unit. */
#include "worker_messages.h"
#include "wwapi.h"

#include "test_assert.h"

#if defined(__unix__) || defined(__APPLE__) || defined(UNIX)
#include <sys/wait.h>
#include <unistd.h>
#define API_DISPATCHER_HAS_FORK 1
#endif

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static atomic_bool             refuse_next;
worker_message_submit_result_e __real_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3)
{
    if (atomicExchangeExplicit(&refuse_next, false, memory_order_acq_rel))
    {
        require(cleanup != NULL, "refused dispatch had no ownership settlement");
        cleanup(arg1, arg2, arg3, kWorkerMessageCancelEnqueueFailure);
        return kWorkerMessageSubmitRejectedCleanupRan;
    }
    return __real_sendWorkerMessageForceQueueWithCleanup(wid, callback, cleanup, arg1, arg2, arg3);
}

typedef struct probe_s
{
    node_api_domain_t         *domain;
    node_api_job_t            *job;
    atomic_bool                submitted;
    atomic_bool                complete;
    atomic_bool                entered;
    atomic_bool                release;
    atomic_uint                calls;
    bool                       hold_handler;
    bool                       refuse_reply;
    wid_t                      owner;
    size_t                     result_size;
    bool                       empty_result;
    node_api_dispatch_status_t expected_status;
} probe_t;

static tunnel_t      target;
static probe_t       probe;
static const uint8_t binary_body[] = {'a', 0, 0xff, 'z'};

static api_result_t echoHandler(tunnel_t *instance, sbuf_t *request, const node_api_call_context_t *context)
{
    require(instance == &target && currentThreadIsWorker(), "handler lacked its event-worker target");
    require(strcmp(context->principal, "operator") == 0 && strcmp(context->operation, "binary") == 0,
            "detached call metadata was corrupted");
    require(context->gateway_config != NULL && context->gateway_node != NULL &&
                strcmp(context->gateway_config, "management") == 0 && strcmp(context->gateway_node, "api") == 0,
            "detached gateway identity was not copied");
    require(sbufGetLength(request) == sizeof(binary_body) &&
                memcmp(sbufGetRawPtr(request), binary_body, sizeof(binary_body)) == 0,
            "binary request bytes changed");
    atomicAddExplicit(&probe.calls, 1, memory_order_relaxed);
    atomicStoreExplicit(&probe.entered, true, memory_order_release);
    if (probe.hold_handler)
        while (! atomicLoadExplicit(&probe.release, memory_order_acquire))
            YIELD_THREAD();
    if (probe.refuse_reply)
        atomicStoreExplicit(&refuse_next, true, memory_order_release);
    if (probe.empty_result)
    {
        bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), request);
        return (api_result_t) {.result_code = kApiResultError};
    }
    if (probe.result_size != 0)
    {
        bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), request);
        request = bufferpoolGetBestFit(getCurrentWorkerBufferPool(), (uint32_t) probe.result_size, 0);
        memset(sbufGetMutablePtr(request), 0xa5, probe.result_size);
        sbufSetLength(request, (uint32_t) probe.result_size);
    }
    return (api_result_t) {.result_code = kApiResultError, .buffer = request};
}

static const node_api_operation_t worker_zero_operation = {.name                  = "binary",
                                                           .handler               = echoHandler,
                                                           .read_only             = true,
                                                           .request_content_type  = "application/octet-stream",
                                                           .response_content_type = "application/octet-stream",
                                                           .response_encoding     = kNodeApiEncodingBase64,
                                                           .execution             = kNodeApiSpecifiedWorker,
                                                           .wid                   = 0};
static const node_api_operation_t worker_one_operation  = {.name                  = "binary",
                                                           .handler               = echoHandler,
                                                           .read_only             = true,
                                                           .request_content_type  = "application/octet-stream",
                                                           .response_content_type = "application/octet-stream",
                                                           .response_encoding     = kNodeApiEncodingBase64,
                                                           .execution             = kNodeApiSpecifiedWorker,
                                                           .wid                   = 1};

static void completion(void *context, uint64_t session, uint64_t request, const node_api_reply_t *reply)
{
    require(context == &probe && currentThreadOwnsWorker(probe.owner), "completion touched a foreign owner");
    require(session == 11 && request == 29, "internal lifetime tokens were corrupted");
    require(reply->status == probe.expected_status, "dispatch returned an incorrect gateway status");
    if (reply->status == kNodeApiDispatchOk)
    {
        require(reply->result_code == kApiResultError, "node error meaning was lost");
        if (probe.empty_result)
            require(reply->body_size == 0 && reply->body == NULL, "empty result gained body bytes");
        else if (probe.result_size != 0)
        {
            require(reply->body_size == probe.result_size, "large result length changed");
            for (size_t i = 0; i < reply->body_size; ++i)
                require(reply->body[i] == 0xa5, "large result byte changed");
        }
        else
            require(reply->body_size == sizeof(binary_body) &&
                        memcmp(reply->body, binary_body, sizeof(binary_body)) == 0,
                    "binary response bytes changed");
    }
    nodeApiJobRelease(probe.job);
    probe.job = NULL;
    atomicStoreExplicit(&probe.complete, true, memory_order_release);
}

static void waitFor(const atomic_bool *flag, const char *message)
{
    const uint64_t deadline = nodeApiNowMs() + 5000;
    while (! atomicLoadExplicit((atomic_bool *) flag, memory_order_acquire) && nodeApiNowMs() < deadline)
    {
        discard wloopProcessEvents(getWorkerLoop(0), 0);
        wwSleepMS(1);
    }
    require(atomicLoadExplicit((atomic_bool *) flag, memory_order_acquire), message);
}

static void waitEmpty(void)
{
    size_t         bytes = 0, jobs = 0;
    const uint64_t deadline = nodeApiNowMs() + 5000;
    do
    {
        discard wloopProcessEvents(getWorkerLoop(0), 0);
        nodeApiDomainGetUsage(probe.domain, &bytes, &jobs);
        if (jobs == 0)
            break;
        wwSleepMS(1);
    } while (nodeApiNowMs() < deadline);
    require(jobs == 0 && bytes == 0, "job settlement leaked a reservation");
}

static void resetProbe(wid_t owner)
{
    memset(&probe, 0, sizeof(probe));
    probe.owner  = owner;
    probe.domain = nodeApiDomainCreate(2 * 1024 * 1024, 4, completion, &probe);
    require(probe.domain != NULL, "domain construction failed");
}

static node_api_job_t *newJob(const node_api_operation_t *operation, uint64_t deadline)
{
    char            config[] = "management";
    char            node[]   = "api";
    node_api_job_t *job      = nodeApiJobCreate(probe.domain,
                                           &target,
                                           operation,
                                           probe.owner,
                                           11,
                                           29,
                                           deadline,
                                           "operator",
                                           config,
                                           node,
                                           binary_body,
                                           sizeof(binary_body),
                                           131072,
                                           262144);
    memset(config, 'x', sizeof(config) - 1);
    memset(node, 'x', sizeof(node) - 1);
    return job;
}

static void startOnWorkerOne(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg1;
    discard arg2;
    discard arg3;
    probe.job = newJob(&worker_zero_operation, nodeApiNowMs() + 5000);
    require(probe.job != NULL && nodeApiJobSubmit(probe.job) == kNodeApiDispatchOk, "cross-worker submission failed");
    atomicStoreExplicit(&probe.submitted, true, memory_order_release);
}

static void testSameAndCrossWorker(void)
{
    resetProbe(0);
    probe.job = newJob(&worker_zero_operation, nodeApiNowMs() + 5000);
    require(probe.job != NULL, "same-worker job creation failed");
    require(nodeApiJobSubmit(probe.job) == kNodeApiDispatchOk, "same-worker submit refused");
    require(atomicLoadRelaxed(&probe.calls) == 0, "same-worker handler ran inline");
    waitFor(&probe.complete, "same-worker reply missing");
    waitEmpty();
    nodeApiDomainDestroy(probe.domain);

    resetProbe(1);
    require(sendWorkerMessageForceQueueWithCleanup(1, startOnWorkerOne, NULL, NULL, NULL, NULL) ==
                kWorkerMessageSubmitAccepted,
            "owner setup refused");
    waitFor(&probe.submitted, "worker-one owner did not submit");
    waitFor(&probe.complete, "worker 1 -> 0 -> 1 reply missing");
    waitEmpty();
    nodeApiDomainDestroy(probe.domain);
}

static void testResultBounds(void)
{
    const size_t sizes[] = {0, 70000, 131072, 131073};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i)
    {
        resetProbe(0);
        probe.result_size  = sizes[i];
        probe.empty_result = sizes[i] == 0;
        if (sizes[i] > 131072)
            probe.expected_status = kNodeApiDispatchResponseTooLarge;
        probe.job = newJob(&worker_zero_operation, nodeApiNowMs() + 5000);
        require(probe.job != NULL && nodeApiJobSubmit(probe.job) == kNodeApiDispatchOk, "bounded result setup failed");
        waitFor(&probe.complete, "bounded result completion missing");
        waitEmpty();
        nodeApiDomainDestroy(probe.domain);
    }
}

static void testAbandonedAndDeadline(void)
{
    resetProbe(0);
    probe.job = newJob(&worker_zero_operation, nodeApiNowMs() + 5000);
    require(probe.job != NULL && nodeApiJobSubmit(probe.job) == kNodeApiDispatchOk, "queued abandon setup failed");
    nodeApiJobAbandon(probe.job);
    nodeApiJobRelease(probe.job);
    probe.job = NULL;
    waitEmpty();
    require(atomicLoadRelaxed(&probe.calls) == 0 && ! atomicLoadRelaxed(&probe.complete),
            "abandoned queued job ran or completed");
    nodeApiDomainDestroy(probe.domain);

    resetProbe(0);
    probe.hold_handler = true;
    probe.job          = newJob(&worker_one_operation, nodeApiNowMs() + 5000);
    require(probe.job != NULL && nodeApiJobSubmit(probe.job) == kNodeApiDispatchOk, "running abandon setup failed");
    waitFor(&probe.entered, "held handler never entered");
    nodeApiJobAbandon(probe.job);
    nodeApiJobRelease(probe.job);
    probe.job    = NULL;
    size_t bytes = 0, jobs = 0;
    nodeApiDomainGetUsage(probe.domain, &bytes, &jobs);
    require(jobs == 1 && bytes > 0, "abandoned running job released its reservation early");
    atomicStoreExplicit(&probe.release, true, memory_order_release);
    waitEmpty();
    require(! atomicLoadRelaxed(&probe.complete), "abandoned running job delivered a reply");
    nodeApiDomainDestroy(probe.domain);

    resetProbe(0);
    probe.expected_status = kNodeApiDispatchTimeout;
    probe.job             = newJob(&worker_zero_operation, nodeApiNowMs());
    require(probe.job != NULL && nodeApiJobSubmit(probe.job) == kNodeApiDispatchOk, "deadline setup failed");
    waitFor(&probe.complete, "queued deadline did not complete");
    waitEmpty();
    require(atomicLoadRelaxed(&probe.calls) == 0, "expired queued handler executed");
    nodeApiDomainDestroy(probe.domain);
}

static void testRefusalAndBudget(void)
{
    resetProbe(0);
    require(nodeApiDomainTryReserve(probe.domain, 2 * 1024 * 1024), "exact domain budget refused");
    require(! nodeApiDomainTryReserve(probe.domain, 1), "full budget admitted another byte");
    require(newJob(&worker_zero_operation, nodeApiNowMs() + 5000) == NULL, "job exceeded aggregate budget");
    nodeApiDomainRelease(probe.domain, 2 * 1024 * 1024);
    probe.job = newJob(&worker_zero_operation, nodeApiNowMs() + 5000);
    require(probe.job != NULL, "refusal job creation failed");
    atomicStoreExplicit(&refuse_next, true, memory_order_release);
    require(nodeApiJobSubmit(probe.job) == kNodeApiDispatchBusy, "target refusal was accepted");
    nodeApiJobRelease(probe.job);
    probe.job = NULL;
    waitEmpty();
    nodeApiDomainDestroy(probe.domain);

    resetProbe(0);
    probe.refuse_reply = true;
    probe.job          = newJob(&worker_zero_operation, nodeApiNowMs() + 5000);
    require(probe.job != NULL && nodeApiJobSubmit(probe.job) == kNodeApiDispatchOk, "reply refusal setup failed");
    waitFor(&probe.entered, "reply refusal handler never ran");
    require(! atomicLoadRelaxed(&probe.complete), "refused reply unexpectedly completed");
    nodeApiJobAbandon(probe.job);
    nodeApiJobRelease(probe.job);
    probe.job = NULL;
    waitEmpty();
    nodeApiDomainClose(probe.domain);
    require(! nodeApiDomainTryReserve(probe.domain, 1), "closed domain admitted memory");
    require(newJob(&worker_zero_operation, nodeApiNowMs() + 5000) == NULL, "closed domain admitted a job");
    nodeApiDomainDestroy(probe.domain);
}

static void initializeRuntime(bool publish_workers)
{
    static char            log_off[]    = "OFF";
    ww_construction_data_t init         = {.workers_count = 2, .ram_profile = 4, .mtu_size = 1500};
    init.internal_logger_data.log_level = log_off;
    init.core_logger_data.log_level     = log_off;
    init.network_logger_data.log_level  = log_off;
    init.dns_logger_data.log_level      = log_off;
    require(wwStartupSucceeded(createGlobalState(init)), "worker runtime failed");
    require(nodeApiRegister(&target, &worker_zero_operation, 1), "test operation registration failed");
    nodeApiFreeze();
    if (publish_workers)
        atomicStoreExplicit(&GSTATE.workers_run_flag, true, memory_order_release);
}

static void stopWorkerZero(void)
{
    const ww_lifecycle_context_t *context = wwLifecycleStartupRollback();
    require(workerInstallApplicationQuiesceRequest(getWorker(0), context) != kWorkerQuiesceRequestUnavailable,
            "worker zero quiescence install failed");
    workerPerformQuiesce(getWorker(0), context);
    require(workerRequestDrain(getWorker(0)), "worker zero drain request failed");
    workerPerformDrain(getWorker(0), context);
    require(workerRequestTeardown(getWorker(0)), "worker zero teardown request failed");
    workerPerformTeardown(getWorker(0));
}

#if defined(API_DISPATCHER_HAS_FORK)
static void shutdownPendingJob(bool running, bool zero_first)
{
    initializeRuntime(running);
    resetProbe(0);
    probe.hold_handler = running;
    probe.job          = newJob(&worker_one_operation, nodeApiNowMs() + 5000);
    require(probe.job != NULL && nodeApiJobSubmit(probe.job) == kNodeApiDispatchOk, "shutdown job submission failed");
    if (running)
        waitFor(&probe.entered, "shutdown handler never entered");
    else
        require(atomicLoadRelaxed(&probe.calls) == 0, "queued shutdown job executed before worker publication");

    nodeApiCloseAdmission();
    nodeApiDomainClose(probe.domain);
    require(newJob(&worker_zero_operation, nodeApiNowMs() + 5000) == NULL, "shutdown gate admitted another handler");
    nodeApiJobAbandon(probe.job);
    nodeApiJobRelease(probe.job);
    probe.job    = NULL;
    size_t bytes = 0, jobs = 0;
    nodeApiDomainGetUsage(probe.domain, &bytes, &jobs);
    require(jobs == 1 && bytes > 0, "pending shutdown job released its reservation before settlement");

    if (zero_first)
    {
        stopWorkerZero();
        nodeApiDomainGetUsage(probe.domain, &bytes, &jobs);
        require(jobs == 1 && bytes > 0, "owner teardown released the target's outstanding reservation");
    }
    if (running)
    {
        require(workerRequestQuiesce(getWorker(1)), "running target quiescence request failed");
        require(workerGetLifecycle(getWorker(1)) < kWorkerLifecycleQuiesced,
                "target acknowledged quiescence while its handler was running");
        atomicStoreExplicit(&probe.release, true, memory_order_release);
    }
    require(workerExitJoin(getWorker(1)), "pending target shutdown failed");
    if (! zero_first)
        stopWorkerZero();

    nodeApiDomainGetUsage(probe.domain, &bytes, &jobs);
    require(jobs == 0 && bytes == 0, "both worker stops left detached job reservations");
    require(atomicLoadRelaxed(&probe.calls) == (running ? 1U : 0U),
            "a queued handler ran after global admission closed");
    require(! atomicLoadRelaxed(&probe.complete), "shutdown delivered an abandoned completion");
    nodeApiDomainDestroy(probe.domain);
    nodeApiUnregister(&target);
    destroyGlobalState();
}

static void testShutdownOrders(void)
{
    static const char *const names[] = {"queued_shutdown_1_then_0",
                                        "queued_shutdown_0_then_1",
                                        "running_shutdown_1_then_0",
                                        "running_shutdown_0_then_1"};
    for (unsigned int index = 0; index < 4; ++index)
    {
        testCaseSet(names[index]);
        const pid_t child = fork();
        require(child >= 0, "shutdown fixture fork failed");
        if (child == 0)
        {
            shutdownPendingJob(index >= 2, (index & 1U) != 0);
            _Exit(0);
        }
        int status = 0;
        require(waitpid(child, &status, 0) == child, "shutdown fixture wait failed");
        require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "pending-job shutdown child failed");
    }
}
#endif

int main(void)
{
#if defined(API_DISPATCHER_HAS_FORK)
    testShutdownOrders();
#endif
    testCaseSet("api_dispatcher_fixture");
    initializeRuntime(true);
    TEST_RUN_CASE(testSameAndCrossWorker);
    TEST_RUN_CASE(testResultBounds);
    TEST_RUN_CASE(testAbandonedAndDeadline);
    TEST_RUN_CASE(testRefusalAndBudget);
    nodeApiCloseAdmission();
    nodeApiUnregister(&target);
    require(workerExitJoin(getWorker(1)), "worker one teardown failed");
    stopWorkerZero();
    destroyGlobalState();
    return 0;
}
