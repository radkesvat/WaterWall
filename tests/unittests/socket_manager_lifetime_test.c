#include "wwapi.h"

#include "socket_manager.h"

static bool     g_fail_sync_init;
static bool     g_fail_after_mutex;
static uint32_t g_sync_acquired;
static uint32_t g_sync_destroyed;

bool socketManagerConstructorTestFailAfterMutex(void);

bool wSyncInitTestShouldFail(void)
{
    const bool fail  = g_fail_sync_init;
    g_fail_sync_init = false;
    return fail;
}

void wSyncInitTestResourceAcquired(void)
{
    ++g_sync_acquired;
}

void wSyncInitTestResourceDestroyed(void)
{
    ++g_sync_destroyed;
}

bool socketManagerConstructorTestFailAfterMutex(void)
{
    const bool fail    = g_fail_after_mutex;
    g_fail_after_mutex = false;
    return fail;
}

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "socket_manager_lifetime_test: %s\n", message);
        exit(1);
    }
}

static void requireBalanced(void)
{
    require(g_sync_acquired == g_sync_destroyed, "manager mutex acquisition/destruction is unbalanced");
}

int main(void)
{
    worker_t workers[2];
    memoryZero(workers, sizeof(workers));
    workers[0].wid            = 0;
    workers[0].has_event_loop = true;
    workers[1].wid            = 1;

    GSTATE.flag_initialized = true;
    GSTATE.workers          = workers;
    GSTATE.workers_count    = ARRAY_SIZE(workers);
    GSTATE.ram_profile      = 1;
    testWorkerBindWID(0);

    require(socketmanagerCreate() != NULL, "real manager create failed");
    require(socketmanagerGet() != NULL, "successful create did not publish the singleton");
    require(g_sync_acquired == 1 && g_sync_destroyed == 0,
            "successful create did not acquire exactly one manager mutex");
    socketmanagerDestroy();
    require(socketmanagerGet() == NULL, "destroy did not clear the singleton");
    requireBalanced();

    require(socketmanagerCreate() != NULL, "manager was not recreatable after destroy");
    socketmanagerDestroy();
    require(g_sync_acquired == 2 && g_sync_destroyed == 2,
            "create/destroy/create did not balance manager mutex resources");

    g_fail_sync_init = true;
    require(socketmanagerCreate() == NULL, "manager accepted a refused mutex construction");
    require(socketmanagerGet() == NULL, "mutex failure published the singleton");
    require(g_sync_acquired == 2 && g_sync_destroyed == 2,
            "mutex failure acquired or destroyed a nonexistent resource");

    g_fail_after_mutex = true;
    require(socketmanagerCreate() == NULL, "manager accepted the first post-mutex constructor failure");
    require(socketmanagerGet() == NULL, "post-mutex failure published the singleton");
    require(g_sync_acquired == 3 && g_sync_destroyed == 3,
            "post-mutex failure did not destroy its acquired resource exactly once");

    require(socketmanagerCreate() != NULL, "post-mutex failure made the manager non-retryable");
    socketmanagerDestroy();
    require(g_sync_acquired == 4 && g_sync_destroyed == 4, "final manager retry leaked its synchronization resource");

    testWorkerUnbindWID();
    GSTATE.flag_initialized = false;
    GSTATE.workers          = NULL;
    GSTATE.workers_count    = 0;

    puts("socket_manager_lifetime_test: all cases passed");
    return 0;
}
