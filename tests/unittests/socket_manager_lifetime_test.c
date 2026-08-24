#include "wwapi.h"

#include "socket_manager.h"

static bool     g_fail_sync_init;
static bool     g_fail_after_mutex;
static bool     g_fail_filter_publication;
static uint32_t g_sync_acquired;
static uint32_t g_sync_destroyed;
static uint32_t g_unpublished_options_released;

bool socketManagerConstructorTestFailAfterMutex(void);
bool socketManagerRegistrationTestFailPublication(void);
void socketManagerRegistrationTestUnpublishedOptionReleased(void);
void socketManagerRegistrationTestSetStarted(bool started);

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

bool socketManagerRegistrationTestFailPublication(void)
{
    const bool fail           = g_fail_filter_publication;
    g_fail_filter_publication = false;
    return fail;
}

void socketManagerRegistrationTestUnpublishedOptionReleased(void)
{
    ++g_unpublished_options_released;
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

static socket_filter_option_t createOwnedFilterOption(bool with_balance_group)
{
    socket_filter_option_t option;
    socketfilteroptionInit(&option);
    option.host           = (char *) "127.0.0.1";
    option.protocol       = IPPROTO_TCP;
    option.port_min       = 4321;
    option.port_max       = 4321;
    option.interface_name = stringDuplicate("loopback-test");
    require(option.interface_name != NULL, "failed to allocate filter interface name");
    if (with_balance_group)
    {
        option.balance_group_name = stringDuplicate("late-registration-test");
        require(option.balance_group_name != NULL, "failed to allocate filter balance-group name");
    }
    require(vec_listener_port_t_push(&option.ports, option.port_min) != NULL,
            "failed to populate owned filter port vector");
    return option;
}

static ww_startup_result_t registerFilterOption(socket_filter_option_t option)
{
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    socketacceptorRegister(NULL, option, NULL);
    return wwStartupContextEnd(&startup);
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

    socketManagerRegistrationTestSetStarted(true);
    require(! wwStartupSucceeded(registerFilterOption(createOwnedFilterOption(true))),
            "late filter registration did not fail startup");
    socketManagerRegistrationTestSetStarted(false);
    require(g_unpublished_options_released == 1, "late filter registration did not release its transferred option");

    g_fail_filter_publication = true;
    require(! wwStartupSucceeded(registerFilterOption(createOwnedFilterOption(false))),
            "refused filter publication did not fail startup");
    require(g_unpublished_options_released == 2, "refused filter publication did not release its copied option");

    require(wwStartupSucceeded(registerFilterOption(createOwnedFilterOption(false))),
            "valid filter registration failed");
    require(g_unpublished_options_released == 2, "successful filter registration released manager-owned options early");

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
