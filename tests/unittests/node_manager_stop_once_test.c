#include "wwapi.h"

#include "managers/node_manager.c" // NOLINT: exercises the private traversal containers

#include "worker_registry_fixture.h"

static test_worker_registry_t g_test_worker_registry;

static unsigned int quiesce_request_calls;
static unsigned int worker_quiesce_calls;
static unsigned int quiesce_wait_calls;
static unsigned int worker_stop_calls;
static unsigned int stop_calls;
static unsigned int worker_post_callbacks;
static unsigned int worker_post_cleanups;
static bool         phase_order_failed;

static const ww_lifecycle_context_t kShutdownContext = {
    .scope        = kWwLifecycleProcessShutdown,
    .close_policy = kWwLifecycleCloseGraceful,
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void workerPostCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg1;
    discard arg2;
    discard arg3;
    ++worker_post_callbacks;
}

static void workerPostCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard reason;
    discard arg1;
    discard arg2;
    discard arg3;
    ++worker_post_cleanups;
}

static void tunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard t;
    require(context == &kShutdownContext, "quiesce request lost its lifecycle context");
    ++quiesce_request_calls;
}

static void tunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard t;
    require(context == &kShutdownContext, "worker quiesce lost its lifecycle context");
    if (quiesce_request_calls != 2 || ! currentThreadIsEventWorkerWID(wid))
    {
        phase_order_failed = true;
    }
    ++worker_quiesce_calls;
}

static void tunnelOnQuiesceWait(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard t;
    require(context == &kShutdownContext, "quiesce wait lost its lifecycle context");
    if (quiesce_request_calls != 2 || worker_quiesce_calls != 2)
    {
        phase_order_failed = true;
    }
    ++quiesce_wait_calls;
}

static void tunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard t;
    require(context == &kShutdownContext, "worker stop lost its lifecycle context");
    if (quiesce_wait_calls != 2 || ! currentThreadIsEventWorkerWID(wid))
    {
        phase_order_failed = true;
    }
    sendWorkerMessageWithCleanup(wid, (WorkerMessageCallback) workerPostCallback, workerPostCleanup, NULL, NULL, NULL);
    require(! sendWorkerMessageTimedWithCleanup(
                wid, (WorkerMessageCallback) workerPostCallback, workerPostCleanup, 10U, NULL, NULL, NULL),
            "worker drain admitted timed work after message admission closed");
    ++worker_stop_calls;
}

static void tunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard t;
    require(context == &kShutdownContext, "final stop lost its lifecycle context");
    if (worker_stop_calls != 2)
    {
        phase_order_failed = true;
    }
    ++stop_calls;
}

static void tunnelFlow(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
}

static void tunnelPayload(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    discard t;
    discard line;
    discard payload;
}

static void tunnelStatus(tunnel_t *t)
{
    discard t;
}

static void tunnelLifecycle(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard t;
    discard context;
}

static void tunnelWorkerLifecycle(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard t;
    discard wid;
    discard context;
}

static void tunnelChain(tunnel_t *t, tunnel_chain_t *chain)
{
    discard t;
    discard chain;
}

static void tunnelIndex(tunnel_t *t, uint16_t index, uint32_t *offset)
{
    discard t;
    discard index;
    discard offset;
}

static tunnel_t completeTunnel(void)
{
    return (tunnel_t) {
        .fnInitU          = tunnelFlow,
        .fnInitD          = tunnelFlow,
        .fnPayloadU       = tunnelPayload,
        .fnPayloadD       = tunnelPayload,
        .fnEstU           = tunnelFlow,
        .fnEstD           = tunnelFlow,
        .fnFinU           = tunnelFlow,
        .fnFinD           = tunnelFlow,
        .fnPauseU         = tunnelFlow,
        .fnPauseD         = tunnelFlow,
        .fnResumeU        = tunnelFlow,
        .fnResumeD        = tunnelFlow,
        .onChain          = tunnelChain,
        .onIndex          = tunnelIndex,
        .onPrepare        = tunnelStatus,
        .onStart          = tunnelStatus,
        .onQuiesceRequest = tunnelLifecycle,
        .onWorkerQuiesce  = tunnelWorkerLifecycle,
        .onQuiesceWait    = tunnelLifecycle,
        .onWorkerStop     = tunnelWorkerLifecycle,
        .onStop           = tunnelLifecycle,
        .onDestroy        = tunnelLifecycle,
    };
}

static void verifyTotalCallbackChecker(void)
{
    tunnel_t complete = completeTunnel();
    require(findMissingTunnelCallback(&complete) == NULL, "a complete callback table was rejected");

#define REQUIRE_MISSING_CALLBACK(slot)                                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        tunnel_t candidate = complete;                                                                                 \
        candidate.slot     = NULL;                                                                                     \
        require(stringCompare(findMissingTunnelCallback(&candidate), #slot) == 0, "missing callback was accepted");    \
    } while (0)

    REQUIRE_MISSING_CALLBACK(fnInitU);
    REQUIRE_MISSING_CALLBACK(fnInitD);
    REQUIRE_MISSING_CALLBACK(fnPayloadU);
    REQUIRE_MISSING_CALLBACK(fnPayloadD);
    REQUIRE_MISSING_CALLBACK(fnEstU);
    REQUIRE_MISSING_CALLBACK(fnEstD);
    REQUIRE_MISSING_CALLBACK(fnFinU);
    REQUIRE_MISSING_CALLBACK(fnFinD);
    REQUIRE_MISSING_CALLBACK(fnPauseU);
    REQUIRE_MISSING_CALLBACK(fnPauseD);
    REQUIRE_MISSING_CALLBACK(fnResumeU);
    REQUIRE_MISSING_CALLBACK(fnResumeD);
    REQUIRE_MISSING_CALLBACK(onChain);
    REQUIRE_MISSING_CALLBACK(onIndex);
    REQUIRE_MISSING_CALLBACK(onPrepare);
    REQUIRE_MISSING_CALLBACK(onStart);
    REQUIRE_MISSING_CALLBACK(onQuiesceRequest);
    REQUIRE_MISSING_CALLBACK(onWorkerQuiesce);
    REQUIRE_MISSING_CALLBACK(onQuiesceWait);
    REQUIRE_MISSING_CALLBACK(onWorkerStop);
    REQUIRE_MISSING_CALLBACK(onStop);
    REQUIRE_MISSING_CALLBACK(onDestroy);

#undef REQUIRE_MISSING_CALLBACK
}

static node_manager_config_t *addConfig(node_manager_t *manager, tunnel_t *tunnel)
{
    tunnel_chain_t *chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    require(chain != NULL, "failed to allocate a synthetic chain");
    chain->tunnels.len     = 1;
    chain->tunnels.tuns[0] = tunnel;
    chain->workers_count   = 1;

    node_manager_config_t *cfg = memoryAllocateZero(sizeof(*cfg));
    require(cfg != NULL, "failed to allocate a synthetic config");
    cfg->chains = vec_chains_t_with_capacity(1);
    vec_chains_t_push(&cfg->chains, chain);
    vec_configs_t_push(&manager->configs, cfg);
    return cfg;
}

static void dropConfig(node_manager_config_t *cfg)
{
    memoryFree(*vec_chains_t_at(&cfg->chains, 0));
    vec_chains_t_drop(&cfg->chains);
    memoryFree(cfg);
}

int main(void)
{
    verifyTotalCallbackChecker();

    tunnel_t first          = completeTunnel();
    tunnel_t second         = completeTunnel();
    first.onQuiesceRequest  = tunnelOnQuiesceRequest;
    first.onWorkerQuiesce   = tunnelOnWorkerQuiesce;
    first.onQuiesceWait     = tunnelOnQuiesceWait;
    first.onWorkerStop      = tunnelOnWorkerStop;
    first.onStop            = tunnelOnStop;
    second.onQuiesceRequest = tunnelOnQuiesceRequest;
    second.onWorkerQuiesce  = tunnelOnWorkerQuiesce;
    second.onQuiesceWait    = tunnelOnQuiesceWait;
    second.onWorkerStop     = tunnelOnWorkerStop;
    second.onStop           = tunnelOnStop;

    node_manager_t *manager = nodemanagerCreate();
    require(manager != NULL, "failed to create the node manager");
    node_manager_config_t *first_cfg  = addConfig(manager, &first);
    node_manager_config_t *second_cfg = addConfig(manager, &second);

    GSTATE.workers_count = 2;
    testWorkerRegistryInstall(&g_test_worker_registry);
    testWorkerBindWID(0);

    nodemanagerQuiesceRequest(&kShutdownContext);
    nodemanagerQuiesceRequest(&kShutdownContext);
    require(quiesce_request_calls == 2, "quiesce request pass was not once-only");

    nodemanagerQuiesceWorker(0, &kShutdownContext);
    require(worker_quiesce_calls == 2, "worker quiesce did not visit every tunnel");

    nodemanagerQuiesceWait(&kShutdownContext);
    nodemanagerQuiesceWait(&kShutdownContext);
    require(quiesce_wait_calls == 2, "quiesce wait pass was not once-only");

    nodemanagerStopWorkerResources(0, &kShutdownContext);
    require(worker_stop_calls == 2, "worker drain did not visit every tunnel");
    require(worker_post_callbacks == 0, "worker drain re-admitted normal callbacks");
    require(worker_post_cleanups == 4, "worker drain refusal cleanup did not settle exactly once");

    nodemanagerStop(&kShutdownContext);
    nodemanagerStop(&kShutdownContext);
    require(stop_calls == 2, "final stop pass was not once-only");
    require(! phase_order_failed, "node lifecycle stages ran out of order or on the wrong worker");

    dropConfig(first_cfg);
    dropConfig(second_cfg);
    vec_configs_t_drop(&manager->configs);
    memoryFree(manager);
    nodemanager_gstate = NULL;

    testWorkerUnbindWID();
    testWorkerRegistryRestore(&g_test_worker_registry);
    GSTATE.workers_count = 0;
    return 0;
}
