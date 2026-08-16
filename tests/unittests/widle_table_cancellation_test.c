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

static void postExpiredItem(idle_table_t *table, wloop_t *timer_loop)
{
    wtimer_t *driver = wtimerAdd(timer_loop, idleCallBack, 1000U, 1);
    twfRequire(driver != NULL, "failed to create the IdleTable delivery driver");
    weventSetUserData(driver, table);
    wloopUpdateTime(timer_loop);
    idleCallBack(driver);
    weventSetUserData(driver, NULL);
    wtimerDelete(driver);
}

static void caseAcceptedCancellationRestoresForOwnerDrain(void)
{
    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, kTestWorkers, kTestBufferSize, kTestBufferSize);

    idle_probe_t  probe = {0};
    idle_table_t *table = idleTableCreate(getWorkerLoop(0));
    idle_item_t  *item  = idletableCreateItem(table, kTestHash, &probe, onExpired, 1, 0);
    twfRequire(item != NULL, "failed to create the accepted-cancellation item");

    postExpiredItem(table, getWorkerLoop(0));
    workerMessagesCloseAdmission(getWorker(1));
    workerMessagesCleanupPending(getWorker(1));

    twfRequire(probe.callbacks == 0, "worker-message cleanup invoked a worker-affine idle callback");
    twfRequire(idletableGetIdleItemByHash(1, table, kTestHash) == item,
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
    idle_table_t *table = idleTableCreate(getWorkerLoop(0));
    idle_item_t  *item  = idletableCreateItem(table, kTestHash, &probe, onExpired, 1, 0);
    twfRequire(item != NULL, "failed to create the immediate-refusal item");
    workerMessagesCloseAdmission(getWorker(1));

    postExpiredItem(table, getWorkerLoop(0));
    twfRequire(probe.callbacks == 0, "foreign refusal invoked the target-worker callback inline");
    twfRequire(idletableGetIdleItemByHash(1, table, kTestHash) == item,
               "foreign refusal did not restore the attached idle item");

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
    idle_table_t *table        = idleTableCreate(getWorkerLoop(0));
    twfRequire(idletableCreateItem(table, kTestHash, &remove_probe, onExpired, 1, 0) != NULL,
               "failed to create the pending-removal item");
    postExpiredItem(table, getWorkerLoop(0));
    twfRequire(idletableRemoveIdleItemByHash(1, table, kTestHash), "failed to detach the pending idle item");
    workerMessagesCleanupPending(getWorker(1));
    twfRequire(remove_probe.callbacks == 0, "explicit removal delivered an expiration callback");
    twfRequire(idletableGetIdleItemByHash(1, table, kTestHash) == NULL,
               "explicit removal reinserted a detached idle item");
    idletableDestroy(table);

    idle_probe_t destroy_probe = {0};
    table                      = idleTableCreate(getWorkerLoop(0));
    twfRequire(idletableCreateItem(table, kTestHash, &destroy_probe, onExpired, 1, 0) != NULL,
               "failed to create the pending-destroy item");
    postExpiredItem(table, getWorkerLoop(0));
    idletableDestroy(table);
    workerMessagesCleanupPending(getWorker(1));
    twfRequire(destroy_probe.callbacks == 0, "table destruction delivered an expiration callback");

    tosWorkerEnvTeardown(&env);
}

static void caseInitialStagingRefusalPreservesAttachedItem(void)
{
    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, kTestWorkers, kTestBufferSize, kTestBufferSize);

    idle_probe_t  probe = {0};
    idle_table_t *table = idleTableCreate(getWorkerLoop(0));
    idle_item_t  *item  = idletableCreateItem(table, kTestHash, &probe, onExpired, 1, 0);
    twfRequire(item != NULL, "failed to create the initial-reservation item");

    idletableTestRefuseNextInitialStagingReserve();
    postExpiredItem(table, getWorkerLoop(0));
    twfRequire(probe.callbacks == 0, "initial staging refusal invoked the expiration callback");
    twfRequire(idletableGetIdleItemByHash(1, table, kTestHash) == item,
               "initial staging refusal changed the owner-visible handle");

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
    idle_table_t *table                = idleTableCreate(getWorkerLoop(0));
    for (unsigned int i = 0; i < kGrowthItems; ++i)
    {
        items[i] = idletableCreateItem(table, kTestHash + i, &probes[i], onExpired, 1, 0);
        twfRequire(items[i] != NULL, "failed to create a staging-growth item");
    }

    idletableTestRefuseNextStagingGrowth();
    postExpiredItem(table, getWorkerLoop(0));

    const wid_t  previous_wid = tosSetCurrentWorker(1);
    discard      wloopProcessEvents(getWorkerLoop(1), 0);
    unsigned int delivered = 0;
    unsigned int restored  = 0;
    for (unsigned int i = 0; i < kGrowthItems; ++i)
    {
        delivered += probes[i].callbacks;
        if (idletableGetIdleItemByHash(1, table, kTestHash + i) == items[i])
        {
            restored++;
        }
    }
    twfRequire(delivered == kGrowthItems - 1, "successfully staged items did not settle exactly once");
    twfRequire(restored == 1, "staging growth refusal did not restore exactly the popped item");

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
    idle_table_t *table = idleTableCreate(getWorkerLoop(0));
    idletableTestRefuseNextCreateHeapPublication();
    twfRequire(idletableCreateItem(table, kTestHash, &probe, onExpired, 1, 0) == NULL,
               "create-time heap refusal published a handle");
    twfRequire(idletableGetIdleItemByHash(1, table, kTestHash) == NULL,
               "create-time heap refusal retained a map entry");

    idle_item_t *item = idletableCreateItem(table, kTestHash, &probe, onExpired, 1, 0);
    twfRequire(item != NULL && idletableGetIdleItemByHash(1, table, kTestHash) == item,
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
    idle_table_t *table                                 = idleTableCreate(getWorkerLoop(0));

    items[0] = idletableCreateItem(table, kTestHash, &probes[0], onExpired, 1, 0);
    twfRequire(items[0] != NULL, "failed to create the pending restoration item");
    for (unsigned int i = 1; i < kRestorationCapacityItems; ++i)
    {
        items[i] = idletableCreateItem(table, kTestHash + i, &probes[i], onExpired, 1, 60000);
        twfRequire(items[i] != NULL, "failed to fill the IdleTable restoration-capacity fixture");
    }

    postExpiredItem(table, getWorkerLoop(0));
    twfRequire(probes[0].callbacks == 0, "staging invoked the pending expiration callback inline");

    items[kRestorationCapacityItems] = idletableCreateItem(
        table, kTestHash + kRestorationCapacityItems, &probes[kRestorationCapacityItems], onExpired, 1, 60000);
    twfRequire(items[kRestorationCapacityItems] != NULL,
               "a pending delivery prevented publication of a later idle item");

    workerMessagesCloseAdmission(getWorker(1));
    workerMessagesCleanupPending(getWorker(1));
    twfRequire(idletableGetIdleItemByHash(1, table, kTestHash) == items[0],
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

int main(void)
{
    caseInitialStagingRefusalPreservesAttachedItem();
    caseStagingGrowthRefusalRestoresPoppedItem();
    caseCreateHeapRefusalRollsBackMapPublication();
    casePendingDeliveryRetainsHeapRestorationCapacity();
    caseAcceptedCancellationRestoresForOwnerDrain();
    caseImmediateForeignRefusalRestoresForOwnerDrain();
    caseDetachedPendingItemsAreFreedWithoutCallback();
    puts("IdleTable cancellation ownership tests passed");
    return 0;
}
