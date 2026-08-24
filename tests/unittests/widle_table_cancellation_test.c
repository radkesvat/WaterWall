#include "tunnel_orderly_shutdown_harness.h"
#include "widle_table.h"

enum
{
    kTestWorkers              = 2,
    kTestBufferSize           = 4096,
    kTestHash                 = 0x51D1E,
    kGrowthItems              = 16,
    kRestorationCapacityItems = 32
};

typedef struct idle_probe_s
{
    unsigned int callbacks;
    wid_t        callback_wid;
} idle_probe_t;

static void onExpired(idle_item_t *item)
{
    idle_probe_t *probe = item->userdata;
    probe->callbacks++;
    probe->callback_wid = getWID();
}

static idle_table_t *createTestTable(void)
{
    idle_table_t *table = idleTableCreate(getWorkerLoop(0));
    idletableTestSetNowMS(table, 1000);
    return table;
}

static idle_item_t *createOwnerItem(idle_table_t *table, hash_t key, idle_probe_t *probe, uint64_t age_ms)
{
    const wid_t  previous = tosSetCurrentWorker(1);
    idle_item_t *item     = idletableCreateItem(table, key, probe, onExpired, 1, age_ms);
    discard      tosSetCurrentWorker(previous);
    return item;
}

static idle_item_t *lookupOwnerItem(idle_table_t *table, hash_t key)
{
    const wid_t  previous = tosSetCurrentWorker(1);
    idle_item_t *item     = idletableGetIdleItemByHash(1, table, key);
    discard      tosSetCurrentWorker(previous);
    return item;
}

static bool removeOwnerItem(idle_table_t *table, hash_t key)
{
    const wid_t previous = tosSetCurrentWorker(1);
    const bool  removed  = idletableRemoveIdleItemByHash(1, table, key);
    discard     tosSetCurrentWorker(previous);
    return removed;
}

static void postExpiredItem(idle_table_t *table)
{
    idletableTestRunExpiry(table);
}

static void cleanupOwnerMessages(void)
{
    const wid_t previous = tosSetCurrentWorker(1);
    workerMessagesCleanupPending(getWorker(1));
    discard tosSetCurrentWorker(previous);
}

static void caseAcceptedCancellationRestoresForOwnerDrain(void)
{
    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, kTestWorkers, kTestBufferSize, kTestBufferSize);

    idle_probe_t  probe = {0};
    idle_table_t *table = createTestTable();
    idle_item_t  *item  = createOwnerItem(table, kTestHash, &probe, 0);
    twfRequire(item != NULL, "failed to create the accepted-cancellation item");

    postExpiredItem(table);
    workerMessagesCloseAdmission(getWorker(1));
    cleanupOwnerMessages();

    twfRequire(probe.callbacks == 0, "worker-message cleanup invoked a worker-affine idle callback");
    twfRequire(lookupOwnerItem(table, kTestHash) == item,
               "accepted cancellation did not restore the attached idle item");

    const wid_t previous_wid = tosSetCurrentWorker(1);
    idletableDrainWorkerItems(table, 1);
    discard tosSetCurrentWorker(previous_wid);
    twfRequire(probe.callbacks == 1 && probe.callback_wid == 1,
               "owner drain did not invoke the restored item on its target worker exactly once");

    idletableDestroy(table);
    tosWorkerEnvTeardown(&env);
}

static void caseImmediateForeignRefusalRestoresForOwnerDrain(void)
{
    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, kTestWorkers, kTestBufferSize, kTestBufferSize);

    idle_probe_t  probe = {0};
    idle_table_t *table = createTestTable();
    idle_item_t  *item  = createOwnerItem(table, kTestHash, &probe, 0);
    twfRequire(item != NULL, "failed to create the immediate-refusal item");
    workerMessagesCloseAdmission(getWorker(1));

    postExpiredItem(table);
    twfRequire(probe.callbacks == 0, "foreign refusal invoked the target-worker callback inline");
    twfRequire(lookupOwnerItem(table, kTestHash) == item, "foreign refusal did not restore the attached idle item");

    const wid_t previous_wid = tosSetCurrentWorker(1);
    idletableDrainWorkerItems(table, 1);
    discard tosSetCurrentWorker(previous_wid);
    twfRequire(probe.callbacks == 1 && probe.callback_wid == 1,
               "owner drain did not settle the foreign-refused item exactly once");

    idletableDestroy(table);
    tosWorkerEnvTeardown(&env);
}

static void caseDetachedPendingItemsAreFreedWithoutCallback(void)
{
    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, kTestWorkers, kTestBufferSize, kTestBufferSize);

    idle_probe_t  remove_probe = {0};
    idle_table_t *table        = createTestTable();
    twfRequire(createOwnerItem(table, kTestHash, &remove_probe, 0) != NULL,
               "failed to create the pending-removal item");
    postExpiredItem(table);
    twfRequire(removeOwnerItem(table, kTestHash), "failed to detach the pending idle item");
    cleanupOwnerMessages();
    twfRequire(remove_probe.callbacks == 0, "explicit removal delivered an expiration callback");
    twfRequire(lookupOwnerItem(table, kTestHash) == NULL, "explicit removal reinserted a detached idle item");
    idletableDestroy(table);

    idle_probe_t destroy_probe = {0};
    table                      = createTestTable();
    twfRequire(createOwnerItem(table, kTestHash, &destroy_probe, 0) != NULL,
               "failed to create the pending-destroy item");
    postExpiredItem(table);
    idletableDestroy(table);
    twfRequire(idletableTestGetLiveTableCount() == 1,
               "destroy reclaimed a table while an expiration message still referenced it");
    cleanupOwnerMessages();
    twfRequire(destroy_probe.callbacks == 0, "table destruction delivered an expiration callback");
    twfRequire(idletableTestGetLiveItemCount() == 0 && idletableTestGetLiveTableCount() == 0,
               "last pending-message cleanup did not reclaim the detached item and table");

    tosWorkerEnvTeardown(&env);
}

static void caseInitialStagingRefusalPreservesAttachedItem(void)
{
    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, kTestWorkers, kTestBufferSize, kTestBufferSize);

    idle_probe_t  probe = {0};
    idle_table_t *table = createTestTable();
    idle_item_t  *item  = createOwnerItem(table, kTestHash, &probe, 0);
    twfRequire(item != NULL, "failed to create the initial-reservation item");

    idletableTestRefuseNextInitialStagingReserve();
    postExpiredItem(table);
    twfRequire(probe.callbacks == 0, "initial staging refusal invoked the expiration callback");
    twfRequire(lookupOwnerItem(table, kTestHash) == item, "initial staging refusal changed the owner-visible handle");

    const wid_t previous_wid = tosSetCurrentWorker(1);
    idletableDrainWorkerItems(table, 1);
    discard tosSetCurrentWorker(previous_wid);
    twfRequire(probe.callbacks == 1 && probe.callback_wid == 1,
               "owner drain did not settle the initial-reservation item once");

    idletableDestroy(table);
    tosWorkerEnvTeardown(&env);
}

static void caseStagingGrowthRefusalRestoresPoppedItem(void)
{
    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, kTestWorkers, kTestBufferSize, kTestBufferSize);

    idle_probe_t  probes[kGrowthItems] = {0};
    idle_item_t  *items[kGrowthItems]  = {0};
    idle_table_t *table                = createTestTable();
    for (unsigned int i = 0; i < kGrowthItems; ++i)
    {
        items[i] = createOwnerItem(table, kTestHash + i, &probes[i], 0);
        twfRequire(items[i] != NULL, "failed to create a staging-growth item");
    }

    idletableTestRefuseNextStagingGrowth();
    postExpiredItem(table);

    tosPumpWorker(&env, 1);
    unsigned int delivered = 0;
    unsigned int restored  = 0;
    for (unsigned int i = 0; i < kGrowthItems; ++i)
    {
        delivered += probes[i].callbacks;
        if (lookupOwnerItem(table, kTestHash + i) == items[i])
        {
            restored++;
        }
    }
    twfRequireEqualU32(delivered, kGrowthItems - 1, "successfully staged items did not settle exactly once");
    twfRequire(restored == 1, "staging growth refusal did not restore exactly the popped item");

    const wid_t previous_wid = tosSetCurrentWorker(1);
    idletableDrainWorkerItems(table, 1);
    discard tosSetCurrentWorker(previous_wid);

    delivered = 0;
    for (unsigned int i = 0; i < kGrowthItems; ++i)
    {
        delivered += probes[i].callbacks;
        twfRequire(probes[i].callback_wid == 1, "a staging-growth callback ran outside its owner worker");
    }
    twfRequire(delivered == kGrowthItems, "owner drain did not settle the restored staging item once");

    idletableDestroy(table);
    tosWorkerEnvTeardown(&env);
}

static void caseCreateHeapRefusalRollsBackMapPublication(void)
{
    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, kTestWorkers, kTestBufferSize, kTestBufferSize);

    idle_probe_t  probe = {0};
    idle_table_t *table = createTestTable();
    idletableTestRefuseNextCreateHeapPublication();
    twfRequire(createOwnerItem(table, kTestHash, &probe, 0) == NULL, "create-time heap refusal published a handle");
    twfRequire(lookupOwnerItem(table, kTestHash) == NULL, "create-time heap refusal retained a map entry");

    idle_item_t *item = createOwnerItem(table, kTestHash, &probe, 0);
    twfRequire(item != NULL && lookupOwnerItem(table, kTestHash) == item,
               "create-time rollback prevented later publication of the same key");

    const wid_t previous_wid = tosSetCurrentWorker(1);
    idletableDrainWorkerItems(table, 1);
    discard tosSetCurrentWorker(previous_wid);
    twfRequire(probe.callbacks == 1, "owner drain did not settle the post-rollback item once");

    idletableDestroy(table);
    tosWorkerEnvTeardown(&env);
}

static void casePendingDeliveryRetainsHeapRestorationCapacity(void)
{
    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, kTestWorkers, kTestBufferSize, kTestBufferSize);

    idle_probe_t  probes[kRestorationCapacityItems + 1] = {0};
    idle_item_t  *items[kRestorationCapacityItems + 1]  = {0};
    idle_table_t *table                                 = createTestTable();

    items[0] = createOwnerItem(table, kTestHash, &probes[0], 0);
    twfRequire(items[0] != NULL, "failed to create the pending restoration item");
    for (unsigned int i = 1; i < kRestorationCapacityItems; ++i)
    {
        items[i] = createOwnerItem(table, kTestHash + i, &probes[i], 60000);
        twfRequire(items[i] != NULL, "failed to fill the IdleTable restoration-capacity fixture");
    }

    postExpiredItem(table);
    twfRequire(probes[0].callbacks == 0, "staging invoked the pending expiration callback inline");

    items[kRestorationCapacityItems] =
        createOwnerItem(table, kTestHash + kRestorationCapacityItems, &probes[kRestorationCapacityItems], 60000);
    twfRequire(items[kRestorationCapacityItems] != NULL,
               "a pending delivery prevented publication of a later idle item");

    workerMessagesCloseAdmission(getWorker(1));
    cleanupOwnerMessages();
    twfRequire(lookupOwnerItem(table, kTestHash) == items[0],
               "cancellation lost the pending item's reserved heap-restoration slot");

    const wid_t previous_wid = tosSetCurrentWorker(1);
    idletableDrainWorkerItems(table, 1);
    discard tosSetCurrentWorker(previous_wid);

    unsigned int delivered = 0;
    for (unsigned int i = 0; i <= kRestorationCapacityItems; ++i)
    {
        delivered += probes[i].callbacks;
        twfRequire(probes[i].callback_wid == 1, "capacity fixture callback ran outside its owner worker");
    }
    twfRequire(delivered == kRestorationCapacityItems + 1,
               "owner drain did not settle every capacity fixture item exactly once");

    idletableDestroy(table);
    tosWorkerEnvTeardown(&env);
}

static void caseOwnerDrainDetachesPendingMessageItem(void)
{
    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, kTestWorkers, kTestBufferSize, kTestBufferSize);

    idle_probe_t  probe = {0};
    idle_table_t *table = createTestTable();
    twfRequire(createOwnerItem(table, kTestHash, &probe, 0) != NULL, "failed to create owner-drain pending item");
    postExpiredItem(table);

    const wid_t previous = tosSetCurrentWorker(1);
    idletableDrainWorkerItems(table, 1);
    discard tosSetCurrentWorker(previous);
    twfRequire(probe.callbacks == 0, "owner drain invoked a message-owned expiration item");

    cleanupOwnerMessages();
    twfRequire(probe.callbacks == 0 && idletableTestGetLiveItemCount() == 0,
               "pending message did not settle the owner-drained item exactly once");

    idletableDestroy(table);
    tosWorkerEnvTeardown(&env);
}

enum
{
    kConcurrentStagedItems = 8,
    kConcurrentRefreshes   = 20000
};

typedef struct concurrent_idle_probe_s
{
    idle_table_t *table;
    idle_probe_t  refresh_probe;
    idle_probe_t  staged_probes[kConcurrentStagedItems];
    atomic_bool   ready;
    atomic_bool   stop;
} concurrent_idle_probe_t;

static WTHREAD_ROUTINE(concurrentOwnerMain)
{
    concurrent_idle_probe_t *probe = userdata;
    testWorkerBindWID(1);

    idle_item_t *refresh_item =
        idletableCreateItem(probe->table, kTestHash + 100U, &probe->refresh_probe, onExpired, 1, 60000);
    twfRequire(refresh_item != NULL, "concurrent owner could not create refresh item");
    for (unsigned int index = 0; index < kConcurrentStagedItems; ++index)
    {
        twfRequire(idletableCreateItem(
                       probe->table, kTestHash + 200U + index, &probe->staged_probes[index], onExpired, 1, 0) != NULL,
                   "concurrent owner could not create staged item");
    }

    atomicStoreExplicit(&probe->ready, true, memory_order_release);
    while (! atomicLoadExplicit(&probe->stop, memory_order_acquire))
    {
        idletableKeepIdleItemForAtleast(probe->table, refresh_item, 60000);
        YIELD_CPU();
    }

    idletableDrainWorkerItems(probe->table, 1);
    testWorkerUnbindWID();
    return 0;
}

static void caseConcurrentRefreshStageRemoveAndDrain(void)
{
    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, kTestWorkers, kTestBufferSize, kTestBufferSize);

    concurrent_idle_probe_t probe = {.table = createTestTable()};
    atomic_init(&probe.ready, false);
    atomic_init(&probe.stop, false);

    wthread_t owner_thread;
    twfRequire(threadCreate(&owner_thread, concurrentOwnerMain, &probe) == kWThreadErrorNone,
               "failed to start concurrent idle owner");
    while (! atomicLoadExplicit(&probe.ready, memory_order_acquire))
    {
        YIELD_THREAD();
    }

    idle_probe_t main_probe = {0};
    idle_item_t *main_item  = idletableCreateItem(probe.table, kTestHash + 300U, &main_probe, onExpired, 0, 60000);
    twfRequire(main_item != NULL, "timer owner could not create its refresh item");

    for (unsigned int refresh = 0; refresh < kConcurrentRefreshes; ++refresh)
    {
        idletableKeepIdleItemForAtleast(probe.table, main_item, 60000);
        if (refresh == kConcurrentRefreshes / 2U)
        {
            postExpiredItem(probe.table);
        }
    }

    atomicStoreExplicit(&probe.stop, true, memory_order_release);
    twfRequire(threadJoin(owner_thread) == 0, "concurrent idle owner did not join");

    twfRequire(idletableRemoveIdleItemByHash(0, probe.table, kTestHash + 300U),
               "timer owner could not remove its live refresh item");
    cleanupOwnerMessages();

    twfRequire(probe.refresh_probe.callbacks == 1 && probe.refresh_probe.callback_wid == 1,
               "owner drain did not settle its live refresh item on worker 1");
    for (unsigned int index = 0; index < kConcurrentStagedItems; ++index)
    {
        twfRequire(probe.staged_probes[index].callbacks == 0,
                   "owner drain or cancellation invoked a message-owned staged item");
    }

    idletableDestroy(probe.table);
    twfRequire(idletableTestGetLiveItemCount() == 0 && idletableTestGetLiveTableCount() == 0,
               "concurrent case retained shared idle allocations");
    tosWorkerEnvTeardown(&env);
}

int main(void)
{
    caseInitialStagingRefusalPreservesAttachedItem();
    caseStagingGrowthRefusalRestoresPoppedItem();
    caseCreateHeapRefusalRollsBackMapPublication();
    casePendingDeliveryRetainsHeapRestorationCapacity();
    caseAcceptedCancellationRestoresForOwnerDrain();
    caseImmediateForeignRefusalRestoresForOwnerDrain();
    caseDetachedPendingItemsAreFreedWithoutCallback();
    caseOwnerDrainDetachesPendingMessageItem();
    caseConcurrentRefreshStageRemoveAndDrain();
    puts("IdleTable cancellation ownership tests passed");
    return 0;
}
