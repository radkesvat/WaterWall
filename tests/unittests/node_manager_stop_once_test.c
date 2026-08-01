/*
 * Node-manager stop-once guard.
 *
 * The shutdown sequence used to reach nodemanagerStop() twice: once from the
 * global-state shutdown callback and once from finishGlobalState(). Node onStop
 * hooks run external cleanup scripts and device shutdown (TunDevice pre-down,
 * route and DNS restoration), so running them twice is not harmless.
 *
 * The duplicate call was removed from finishGlobalState(), and nodemanagerStop()
 * additionally carries a defensive stop-once guard. This test pins the guard by
 * driving a synthetic config through the manager's own storage: node_manager.c
 * is included directly so the private config/chain containers are reachable, and
 * the definitions here take precedence over the ones in libww at link time.
 */

#include "wwapi.h"

#include "managers/node_manager.c" // NOLINT: needs the private config containers

static unsigned int stop_calls_first;
static unsigned int stop_calls_second;
static unsigned int worker_stop_calls;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void firstTunnelOnStop(tunnel_t *t)
{
    discard t;
    stop_calls_first++;
}

static void secondTunnelOnStop(tunnel_t *t)
{
    discard t;
    stop_calls_second++;
}

static void tunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    discard t;
    discard wid;
    worker_stop_calls++;
}

int main(void)
{
    tunnel_t first  = {0};
    tunnel_t second = {0};

    first.onStop        = firstTunnelOnStop;
    first.onWorkerStop  = tunnelOnWorkerStop;
    second.onStop       = secondTunnelOnStop;
    second.onWorkerStop = tunnelOnWorkerStop;

    tunnel_chain_t *chain  = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    chain->tunnels.len     = 2;
    chain->tunnels.tuns[0] = &first;
    chain->tunnels.tuns[1] = &second;
    chain->workers_count   = 1;

    node_manager_config_t *cfg = memoryAllocateZero(sizeof(node_manager_config_t));
    cfg->chains                = vec_chains_t_with_capacity(2);
    vec_chains_t_push(&cfg->chains, chain);

    node_manager_t *manager = nodemanagerCreate();
    require(manager != NULL, "failed to create the node manager");
    vec_configs_t_push(&manager->configs, cfg);

    // A tunnel onStop hook runs exactly once, even though the shutdown path may
    // reach nodemanagerStop() more than once.
    nodemanagerStop();
    require(stop_calls_first == 1, "the first tunnel onStop hook did not run exactly once");
    require(stop_calls_second == 1, "the second tunnel onStop hook did not run exactly once");

    nodemanagerStop();
    nodemanagerStop();
    require(stop_calls_first == 1, "a repeated nodemanagerStop() re-ran the first tunnel onStop hook");
    require(stop_calls_second == 1, "a repeated nodemanagerStop() re-ran the second tunnel onStop hook");

    // Worker-local teardown is a separate concern and must still run for the
    // owning worker after the process-wide stop already happened.
    tl_wid = 0;
    nodemanagerStopWorkerResources(0);
    require(worker_stop_calls == 2, "onWorkerStop did not run once per tunnel on the owning worker");

    vec_chains_t_drop(&cfg->chains);
    memoryFree(chain);
    memoryFree(cfg);
    vec_configs_t_drop(&manager->configs);
    memoryFree(manager);
    nodemanager_gstate = NULL;

    return 0;
}
