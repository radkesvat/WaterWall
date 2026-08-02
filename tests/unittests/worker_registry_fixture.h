#pragma once

/*
 * Test-only fake worker registry.
 *
 * Unit tests that stub GSTATE instead of calling createGlobalState() set
 * GSTATE.workers_count and GSTATE.shortcut_* by hand. The worker identity
 * predicates read the worker table itself (worker_t::has_event_loop), so a stub
 * without a table is correctly reported as "not an event worker" and every
 * checked accessor - getCurrentEventWorkerBufferPool(), reuseBuffer(),
 * lineIsOnCurrentEventWorker(), the tunnel-API helpers - refuses to run.
 *
 * This fixture publishes a table that matches the stubbed counts: slots
 * [0, getWorkersCount()) are ordinary event workers and the final slot is an
 * lwIP-style pseudo-worker, exactly as createGlobalState() lays them out.
 *
 * Usage:
 *
 *     GSTATE.workers_count = 2;                  // 1 ordinary worker + lwIP
 *     testWorkerRegistryInstall(&env->registry); // publish the table
 *     testWorkerBindWID(0);
 *     ...
 *     testWorkerRegistryRestore(&env->registry);
 */

#include "global_state.h"
#include "worker.h"

enum
{
    kTestWorkerRegistryMaxSlots = 8
};

typedef struct test_worker_registry_s
{
    worker_t  slots[kTestWorkerRegistryMaxSlots];
    worker_t *saved_workers;
    uint8_t   saved_flag_initialized;
    bool      installed;
} test_worker_registry_t;

/**
 * @brief Publishes a fake worker table matching the current GSTATE.workers_count.
 *
 * Call after GSTATE.workers_count has been stubbed. Slots below
 * getWorkersCount() advertise an event loop; the last slot does not, so it
 * behaves like the lwIP pseudo-worker for the identity predicates.
 */
static inline void testWorkerRegistryInstall(test_worker_registry_t *registry)
{
    assert(registry != NULL);
    assert(GSTATE.workers_count >= 1 && GSTATE.workers_count <= kTestWorkerRegistryMaxSlots);

    registry->saved_workers          = GSTATE.workers;
    registry->saved_flag_initialized = GSTATE.flag_initialized;
    registry->installed              = true;

    const wid_t total = getTotalWorkersCount();

    /*
     * Production reserves the last slot for the lwIP pseudo-worker. A stub that
     * declares a single slot has no lwIP worker at all, so treat that slot as an
     * ordinary event worker rather than leaving the table with no event workers.
     */
    const wid_t ordinary = (total > 1) ? (wid_t) (total - 1) : total;

    for (wid_t wid = 0; wid < total; ++wid)
    {
        registry->slots[wid] = (worker_t) {.wid = wid, .has_event_loop = (wid < ordinary)};
    }

    GSTATE.workers          = registry->slots;
    GSTATE.flag_initialized = 1;
}

/**
 * @brief Publishes a caller-owned worker table.
 *
 * For tests that need real loops, pools or message queues in their worker slots
 * and therefore build the table themselves. It only takes care of publishing it
 * together with flag_initialized, which the identity predicates also require.
 */
static inline void testWorkerRegistryInstallTable(test_worker_registry_t *registry, worker_t *workers)
{
    assert(registry != NULL && workers != NULL);

    registry->saved_workers          = GSTATE.workers;
    registry->saved_flag_initialized = GSTATE.flag_initialized;
    registry->installed              = true;

    GSTATE.workers          = workers;
    GSTATE.flag_initialized = 1;
}

/**
 * @brief Restores whatever worker table was published before the fixture ran.
 */
static inline void testWorkerRegistryRestore(test_worker_registry_t *registry)
{
    assert(registry != NULL);
    if (! registry->installed)
    {
        return;
    }

    GSTATE.workers          = registry->saved_workers;
    GSTATE.flag_initialized = registry->saved_flag_initialized;
    registry->installed     = false;
}
