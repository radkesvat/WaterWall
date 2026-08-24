#include "local_widle_table.h"
#include "widle_table.h"
#include "wwapi.h"

enum
{
    kContractWorkers   = 2,
    kContractBufSize   = 4096,
    kContractBaseKey   = 0x1D1E0000,
    kContractPumpLimit = 8
};

typedef struct contract_env_s
{
    master_pool_t             *large_masters[kContractWorkers];
    master_pool_t             *small_masters[kContractWorkers];
    master_pool_t             *message_master;
    master_pool_t             *wios_master;
    buffer_pool_t             *pools[kContractWorkers + 1];
    wloop_t                   *loops[kContractWorkers + 1];
    threadsafe_generic_pool_t *wios_pools[kContractWorkers + 1];
    worker_t                   workers[kContractWorkers + 1];
} contract_env_t;

typedef enum contract_impl_e
{
    kContractLocal,
    kContractShared
} contract_impl_e;

typedef enum contract_action_e
{
    kContractTerminal,
    kContractExtendOnce,
    kContractRemoveSelf,
    kContractRemoveOther
} contract_action_e;

typedef struct contract_table_s contract_table_t;

typedef struct contract_probe_s
{
    contract_table_t        *table;
    struct contract_probe_s *other;
    void                    *authoritative_item;
    hash_t                   key;
    contract_action_e        action;
    unsigned int             callbacks;
    wid_t                    callback_wid;
} contract_probe_t;

struct contract_table_s
{
    contract_env_t *env;
    contract_impl_e impl;
    union {
        local_idle_table_t *local;
        idle_table_t       *shared;
    } value;
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        fflush(stderr);
        exit(1);
    }
}

static wid_t setCurrentWorker(wid_t wid)
{
    const wid_t previous = getWID();
    testWorkerBindWID(wid);
    return previous;
}

static void pumpWorker(contract_env_t *env, wid_t wid)
{
    const wid_t previous = setCurrentWorker(wid);
    for (unsigned int iteration = 0; iteration < kContractPumpLimit; ++iteration)
    {
        discard wloopProcessEvents(env->loops[wid], 0);
    }
    discard setCurrentWorker(previous);
}

static void contractEnvSetup(contract_env_t *env)
{
    memoryZero(env, sizeof(*env));

    env->message_master = masterpoolCreateWithCapacity(16);
    env->wios_master    = masterpoolCreateWithCapacity(16);
    require(env->message_master != NULL && env->wios_master != NULL, "failed to create shared test pools");
    workerMessagesInstallMasterPoolCallbacks(env->message_master);

    GSTATE.flag_initialized      = true;
    GSTATE.workers               = env->workers;
    GSTATE.workers_count         = kContractWorkers + 1U;
    GSTATE.shortcut_buffer_pools = env->pools;
    GSTATE.shortcut_loops        = env->loops;
    GSTATE.shortcut_wios_pools   = env->wios_pools;
    GSTATE.masterpool_messages   = env->message_master;

    for (wid_t wid = 0; wid < kContractWorkers; ++wid)
    {
        env->large_masters[wid] = masterpoolCreateWithCapacity(8);
        env->small_masters[wid] = masterpoolCreateWithCapacity(8);
        require(env->large_masters[wid] != NULL && env->small_masters[wid] != NULL,
                "failed to create worker buffer masters");

        env->pools[wid] =
            bufferpoolCreate(env->large_masters[wid], env->small_masters[wid], 4, kContractBufSize, kContractBufSize);
        require(env->pools[wid] != NULL, "failed to create worker buffer pool");

        env->wios_pools[wid] =
            threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(env->wios_master, sizeof(wio_t), 8);
        require(env->wios_pools[wid] != NULL, "failed to create worker wio pool");

        env->loops[wid] = wloopCreate(WLOOP_FLAG_AUTO_FREE, env->pools[wid], wid);
        require(env->loops[wid] != NULL, "failed to create worker loop");
        env->loops[wid]->status = WLOOP_STATUS_RUNNING;

        env->workers[wid].wid            = wid;
        env->workers[wid].loop           = env->loops[wid];
        env->workers[wid].buffer_pool    = env->pools[wid];
        env->workers[wid].wios_pool      = env->wios_pools[wid];
        env->workers[wid].has_event_loop = true;
        mutexInit(&env->workers[wid].control_mutex);
        workerMessagesInit(&env->workers[wid]);
        workerMessagesOpenAdmission(&env->workers[wid]);
    }

    testWorkerBindWID(0);
}

static void contractEnvTeardown(contract_env_t *env)
{
    for (wid_t wid = 0; wid < kContractWorkers; ++wid)
    {
        workerMessagesCloseAdmission(&env->workers[wid]);
        const wid_t previous = setCurrentWorker(wid);
        workerMessagesCleanupPending(&env->workers[wid]);
        discard setCurrentWorker(previous);
        workerMessagesDestroy(&env->workers[wid]);
        mutexDestroy(&env->workers[wid].control_mutex);
    }

    for (wid_t wid = 0; wid < kContractWorkers; ++wid)
    {
        wloopDestroy(&env->loops[wid]);
    }

    testWorkerUnbindWID();
    GSTATE.flag_initialized      = false;
    GSTATE.workers               = NULL;
    GSTATE.shortcut_buffer_pools = NULL;
    GSTATE.shortcut_loops        = NULL;
    GSTATE.shortcut_wios_pools   = NULL;
    GSTATE.masterpool_messages   = NULL;

    for (wid_t wid = 0; wid < kContractWorkers; ++wid)
    {
        threadsafegenericpoolDestroy(env->wios_pools[wid]);
        bufferpoolDestroy(env->pools[wid]);
        masterpoolMakeEmpty(env->large_masters[wid]);
        masterpoolMakeEmpty(env->small_masters[wid]);
        masterpoolDestroy(env->large_masters[wid]);
        masterpoolDestroy(env->small_masters[wid]);
    }
    masterpoolMakeEmpty(env->wios_master);
    masterpoolMakeEmpty(env->message_master);
    masterpoolDestroy(env->wios_master);
    masterpoolDestroy(env->message_master);
}

static bool contractRemove(contract_probe_t *probe);
static void contractKeep(contract_table_t *table, void *item, uint64_t age_ms);

static void contractOnCallback(contract_probe_t *probe, void *item)
{
    require(probe != NULL && probe->authoritative_item == item, "callback received a stale owner slot");
    probe->callbacks++;
    probe->callback_wid = getWID();

    if (probe->action == kContractExtendOnce && probe->callbacks == 1)
    {
        contractKeep(probe->table, item, 50);
        return;
    }

    if (probe->action == kContractRemoveSelf)
    {
        require(contractRemove(probe), "expiry callback could not remove itself");
        return;
    }

    if (probe->action == kContractRemoveOther)
    {
        require(probe->other != NULL && contractRemove(probe->other),
                "expiry callback could not remove another active item");
    }

    probe->authoritative_item = NULL;
}

static void localContractCallback(local_idle_item_t *item)
{
    contractOnCallback(item->userdata, item);
}

static void sharedContractCallback(idle_item_t *item)
{
    contractOnCallback(item->userdata, item);
}

static void contractTableCreate(contract_table_t *table, contract_env_t *env, contract_impl_e impl)
{
    *table = (contract_table_t) {.env = env, .impl = impl};
    if (impl == kContractLocal)
    {
        table->value.local = localIdleTableCreate(env->loops[0]);
    }
    else
    {
        table->value.shared = idleTableCreate(env->loops[0]);
    }
}

static void contractSetNow(contract_table_t *table, uint64_t now_ms)
{
    if (table->impl == kContractLocal)
    {
        localidletableTestSetNowMS(table->value.local, now_ms);
    }
    else
    {
        idletableTestSetNowMS(table->value.shared, now_ms);
    }
}

static void *contractCreate(contract_table_t *table, contract_probe_t *probe, hash_t key, uint64_t age_ms)
{
    probe->table = table;
    probe->key   = key;

    void *item;
    if (table->impl == kContractLocal)
    {
        item = localidletableCreateItem(table->value.local, key, probe, localContractCallback, age_ms);
    }
    else
    {
        item = idletableCreateItem(table->value.shared, key, probe, sharedContractCallback, 0, age_ms);
    }
    probe->authoritative_item = item;
    return item;
}

static void *contractLookup(contract_table_t *table, hash_t key)
{
    if (table->impl == kContractLocal)
    {
        return localidletableGetIdleItemByHash(table->value.local, key);
    }
    return idletableGetIdleItemByHash(0, table->value.shared, key);
}

static void contractKeep(contract_table_t *table, void *item, uint64_t age_ms)
{
    if (table->impl == kContractLocal)
    {
        localidletableKeepIdleItemForAtleast(table->value.local, item, age_ms);
    }
    else
    {
        idletableKeepIdleItemForAtleast(table->value.shared, item, age_ms);
    }
}

static uint64_t contractDeadline(contract_table_t *table, void *item)
{
    if (table->impl == kContractLocal)
    {
        return localidletableTestGetDeadline(item);
    }
    return idletableTestGetDeadline(item);
}

static bool contractRemove(contract_probe_t *probe)
{
    void *item = probe->authoritative_item;
    if (item == NULL)
    {
        return false;
    }
    probe->authoritative_item = NULL;

    if (probe->table->impl == kContractLocal)
    {
        return localidletableRemoveIdleItem(probe->table->value.local, item);
    }
    return idletableRemoveIdleItemByHash(0, probe->table->value.shared, probe->key);
}

static size_t contractActiveCount(contract_table_t *table)
{
    if (table->impl == kContractLocal)
    {
        return localidletableGetItemCount(table->value.local);
    }
    return idletableTestGetActiveItemCount(table->value.shared);
}

static unsigned int contractLiveItemCount(contract_table_t *table)
{
    if (table->impl == kContractLocal)
    {
        return localidletableTestGetLiveItemCount();
    }
    return idletableTestGetLiveItemCount();
}

static void contractRunExpiry(contract_table_t *table)
{
    if (table->impl == kContractLocal)
    {
        localidletableTestRunExpiry(table->value.local);
    }
    else
    {
        idletableTestRunExpiry(table->value.shared);
        pumpWorker(table->env, 0);
    }
}

static void contractDrain(contract_table_t *table)
{
    if (table->impl == kContractLocal)
    {
        localidletableDrainItems(table->value.local);
    }
    else
    {
        idletableDrainWorkerItems(table->value.shared, 0);
    }
}

static void contractDestroy(contract_table_t *table)
{
    if (table->impl == kContractLocal)
    {
        localidletableDestroy(table->value.local);
        table->value.local = NULL;
    }
    else
    {
        idletableDestroy(table->value.shared);
        table->value.shared = NULL;
    }
}

static void runGlobalKeyNamespaceCase(contract_table_t *table)
{
    if (table->impl != kContractShared)
    {
        return;
    }

    contract_probe_t owner_zero = {0};
    idle_item_t     *first      = contractCreate(table, &owner_zero, kContractBaseKey + 50U, 5000);
    require(first != NULL, "failed to create global-key owner item");

    contract_probe_t owner_one = {.table = table, .key = kContractBaseKey + 50U};
    const wid_t      previous  = setCurrentWorker(1);
    idle_item_t     *duplicate =
        idletableCreateItem(table->value.shared, owner_one.key, &owner_one, sharedContractCallback, 1, 5000);
    require(duplicate == NULL, "shared key namespace accepted the same key for a second WID");
    require(idletableGetIdleItemByHash(1, table->value.shared, owner_one.key) == NULL,
            "foreign-WID lookup exposed the first owner's item");
    discard setCurrentWorker(previous);

    require(contractLookup(table, owner_zero.key) == first, "duplicate create hid the original shared item");
    require(contractRemove(&owner_zero), "failed to remove original shared key owner");
}

static void runContractCases(contract_env_t *env, contract_impl_e impl)
{
    contract_table_t table;
    contractTableCreate(&table, env, impl);

    contractSetNow(&table, 1000);
    contract_probe_t first      = {0};
    void            *first_item = contractCreate(&table, &first, kContractBaseKey, 100);
    require(first_item != NULL && contractLookup(&table, first.key) == first_item,
            "successful create was not visible through lookup");

    contract_probe_t duplicate = {0};
    require(contractCreate(&table, &duplicate, first.key, 100) == NULL, "duplicate key was accepted by the idle table");
    require(contractLookup(&table, first.key) == first_item && contractActiveCount(&table) == 1,
            "duplicate rejection partially changed publication");
    require(contractDeadline(&table, first_item) == 1100, "initial deadline did not use the deterministic clock");

    contractSetNow(&table, 1050);
    contractKeep(&table, first_item, 10);
    require(contractDeadline(&table, first_item) == 1100, "short refresh shortened a later deadline");
    contractSetNow(&table, 1090);
    contractKeep(&table, first_item, 50);
    require(contractDeadline(&table, first_item) == 1140, "deadline extension did not advance expiration");

    require(contractRemove(&first), "explicit removal failed");
    require(contractLookup(&table, first.key) == NULL && contractActiveCount(&table) == 0,
            "explicit removal did not synchronously clear lookup");
    contractSetNow(&table, 5000);
    contractRunExpiry(&table);
    require(first.callbacks == 0, "explicit removal delivered an expiration callback");

    contract_probe_t reused = {0};
    require(contractCreate(&table, &reused, first.key, 100) != NULL, "removed key could not be reused");
    require(contractRemove(&reused), "reused key could not be removed");

    contractSetNow(&table, UINT64_MAX - 5U);
    contract_probe_t saturated      = {0};
    void            *saturated_item = contractCreate(&table, &saturated, kContractBaseKey + 1U, 10);
    require(saturated_item != NULL && contractDeadline(&table, saturated_item) == UINT64_MAX,
            "near-overflow age wrapped instead of saturating");
    require(contractRemove(&saturated), "failed to remove near-overflow item");

    contractSetNow(&table, 1000);
    contract_probe_t maximum_age  = {0};
    void            *maximum_item = contractCreate(&table, &maximum_age, kContractBaseKey + 2U, UINT64_MAX);
    require(maximum_item != NULL && contractDeadline(&table, maximum_item) == UINT64_MAX,
            "UINT64_MAX age wrapped instead of saturating");
    require(contractRemove(&maximum_age), "failed to remove maximum-age item");

    contract_probe_t natural = {0};
    require(contractCreate(&table, &natural, kContractBaseKey + 3U, 100) != NULL,
            "failed to create natural-expiration item");
    contractSetNow(&table, 1099);
    contractRunExpiry(&table);
    require(natural.callbacks == 0, "item expired before its deadline");
    contractSetNow(&table, 1100);
    contractRunExpiry(&table);
    require(natural.callbacks == 1 && natural.callback_wid == 0 && natural.authoritative_item == NULL,
            "natural expiration did not settle exactly once on the owner worker");
    contractRunExpiry(&table);
    require(natural.callbacks == 1, "natural expiration was delivered more than once");

    contractSetNow(&table, 1200);
    contract_probe_t   extending             = {.action = kContractExtendOnce};
    const unsigned int live_before_extension = contractLiveItemCount(&table);
    void              *extending_item        = contractCreate(&table, &extending, kContractBaseKey + 4U, 0);
    require(extending_item != NULL, "failed to create self-extending item");
    contractRunExpiry(&table);
    require(extending.callbacks == 1 && extending.authoritative_item == extending_item &&
                contractLookup(&table, extending.key) == extending_item &&
                contractDeadline(&table, extending_item) == 1250 &&
                contractLiveItemCount(&table) == live_before_extension + 1U,
            "expiration callback did not restore its self-extension");
    contractSetNow(&table, 1249);
    contractRunExpiry(&table);
    require(extending.callbacks == 1, "self-extended item expired before its new deadline");
    contractSetNow(&table, 1250);
    contractRunExpiry(&table);
    require(extending.callbacks == 2 && extending.authoritative_item == NULL,
            "self-extended item was not delivered once at its new deadline");

    contractSetNow(&table, 1300);
    contract_probe_t self_removing = {.action = kContractRemoveSelf};
    require(contractCreate(&table, &self_removing, kContractBaseKey + 5U, 0) != NULL,
            "failed to create self-removing item");
    contractRunExpiry(&table);
    require(self_removing.callbacks == 1 && self_removing.authoritative_item == NULL &&
                contractLookup(&table, self_removing.key) == NULL,
            "expiration callback did not remove itself exactly once");

    contractSetNow(&table, 1400);
    contract_probe_t target  = {0};
    contract_probe_t remover = {.action = kContractRemoveOther, .other = &target};
    require(contractCreate(&table, &target, kContractBaseKey + 7U, 100) != NULL,
            "failed to create callback-removal target");
    require(contractCreate(&table, &remover, kContractBaseKey + 6U, 0) != NULL, "failed to create callback remover");
    contractRunExpiry(&table);
    require(remover.callbacks == 1 && target.callbacks == 0 && target.authoritative_item == NULL &&
                contractActiveCount(&table) == 0,
            "one callback did not suppress and remove another active item");

    contractSetNow(&table, 1500);
    contract_probe_t drained_one = {0};
    contract_probe_t drained_two = {0};
    require(contractCreate(&table, &drained_one, kContractBaseKey + 8U, 5000) != NULL &&
                contractCreate(&table, &drained_two, kContractBaseKey + 9U, 5000) != NULL,
            "failed to create drain items");
    contractDrain(&table);
    require(drained_one.callbacks == 1 && drained_two.callbacks == 1 && drained_one.authoritative_item == NULL &&
                drained_two.authoritative_item == NULL && contractActiveCount(&table) == 0,
            "drain did not settle every applicable item exactly once");

    runGlobalKeyNamespaceCase(&table);

    contractSetNow(&table, 1600);
    contract_probe_t destroyed_live = {0};
    require(contractCreate(&table, &destroyed_live, kContractBaseKey + 10U, 5000) != NULL,
            "failed to create live item for table destruction");
    require(contractActiveCount(&table) == 1, "live destruction fixture was not active");
    destroyed_live.authoritative_item = NULL;
    contractDestroy(&table);
    require(destroyed_live.callbacks == 0, "table destruction invoked a live item's expiration callback");

    if (impl == kContractLocal)
    {
        require(localidletableTestGetLiveItemCount() == 0 && localidletableTestGetLiveTableCount() == 0,
                "local table destroy retained an item or table allocation");
    }
    else
    {
        require(idletableTestGetLiveItemCount() == 0 && idletableTestGetLiveTableCount() == 0,
                "shared table destroy retained an item or table allocation");
    }
}

int main(void)
{
    contract_env_t env;
    contractEnvSetup(&env);
    runContractCases(&env, kContractLocal);
    runContractCases(&env, kContractShared);
    contractEnvTeardown(&env);
    puts("idle_table_contract_test: all cases passed");
    return 0;
}
