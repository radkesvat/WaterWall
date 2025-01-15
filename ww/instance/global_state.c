#include "global_state.h"







ww_global_state_t global_ww_state = {0};

void setWW(struct ww_global_state_s *state)
{
    assert(! GSTATE.initialized && state->initialized);
    GSTATE = *state;

    setCoreLogger(GSTATE.core_logger);
    setNetworkLogger(GSTATE.network_logger);
    setDnsLogger(GSTATE.dns_logger);
    setInternalLogger(GSTATE.ww_logger);
    setSignalManager(GSTATE.signal_manager);
    setSocketManager(GSTATE.socekt_manager);
    setNodeManager(GSTATE.node_manager);
}


static void initializeShortCuts(void)
{
    assert(GSTATE.initialized);

    static const int kShourtcutsCount = 5;
    const int        total_workers    = WORKERS_COUNT;

    void **space = (void **) memoryAllocate(sizeof(void *) * kShourtcutsCount * total_workers);

    GSTATE.shortcut_loops              = (wloop_t **) (space + (0ULL * total_workers));
    GSTATE.shortcut_buffer_pools       = (buffer_pool_t **) (space + (1ULL * total_workers));
    GSTATE.shortcut_context_pools      = (generic_pool_t **) (space + (2ULL * total_workers));
    GSTATE.shortcut_line_pools         = (generic_pool_t **) (space + (3ULL * total_workers));
    GSTATE.shortcut_pipeline_msg_pools = (generic_pool_t **) (space + (4ULL * total_workers));
}

static void initializeMasterPools(void)
{
    assert(GSTATE.initialized);

    GSTATE.masterpool_buffer_pools_large = newMasterPoolWithCap(2 * ((0) + GSTATE.ram_profile));
    GSTATE.masterpool_buffer_pools_small = newMasterPoolWithCap(2 * ((0) + GSTATE.ram_profile));
    GSTATE.masterpool_context_pools      = newMasterPoolWithCap(2 * ((16) + GSTATE.ram_profile));
    GSTATE.masterpool_line_pools         = newMasterPoolWithCap(2 * ((8) + GSTATE.ram_profile));
    GSTATE.masterpool_pipeline_msg_pools = newMasterPoolWithCap(2 * ((8) + GSTATE.ram_profile));
}

void createGlobalState(const ww_construction_data_t init_data)
{
    GSTATE.initialized = true;

    // [Section] loggers
    {
        GSTATE.ww_logger = createInternalLogger(NULL, true);

        if (init_data.core_logger_data.log_file_path)
        {
            GSTATE.core_logger =
                createCoreLogger(init_data.core_logger_data.log_file_path, init_data.core_logger_data.log_console);

            stringUpperCase(init_data.core_logger_data.log_level);
            setCoreLoggerLevelByStr(init_data.core_logger_data.log_level);
        }
        if (init_data.network_logger_data.log_file_path)
        {
            GSTATE.network_logger = createNetworkLogger(init_data.network_logger_data.log_file_path,
                                                        init_data.network_logger_data.log_console);

            stringUpperCase(init_data.network_logger_data.log_level);
            setNetworkLoggerLevelByStr(init_data.network_logger_data.log_level);

            // libhv has a separate logger, attach it to the network logger
            loggerSetLevelByString(hv_default_logger(), init_data.network_logger_data.log_level);
            loggerSetHandler(hv_default_logger(), getNetworkLoggerHandle());
        }
        if (init_data.dns_logger_data.log_file_path)
        {
            GSTATE.dns_logger =
                createDnsLogger(init_data.dns_logger_data.log_file_path, init_data.dns_logger_data.log_console);

            stringUpperCase(init_data.dns_logger_data.log_level);
            setDnsLoggerLevelByStr(init_data.dns_logger_data.log_level);
        }
    }

    // workers and pools creation
    {
        WORKERS_COUNT      = init_data.workers_count;
        GSTATE.ram_profile = init_data.ram_profile;

        if (WORKERS_COUNT <= 0 || WORKERS_COUNT > (254))
        {
            LOGW("workers count was not in valid range, value: %u range:[1 - %d]\n", WORKERS_COUNT, (254));
            WORKERS_COUNT = (254);
        }

        WORKERS = (worker_t *) memoryAllocate(sizeof(worker_t) * (WORKERS_COUNT));

        initializeShortCuts();
        initializeMasterPools();

        for (unsigned int i = 0; i < WORKERS_COUNT; ++i)
        {
            initalizeWorker(getWorker(i), i);
        }
    }

    GSTATE.signal_manager = createSignalManager();
    startSignalManager();

    GSTATE.socekt_manager = createSocketManager();
    GSTATE.node_manager   = createNodeManager();

    // Spawn all workers except main worker which is current thread
    {
        WORKERS[0].thread = (wthread_t) NULL;
        for (unsigned int i = 1; i < WORKERS_COUNT; ++i)
        {
            WORKERS[i].thread = threadCreate(worker_thread, getWorker(i));
        }
    }
}


_Noreturn void runMainThread(void)
{
    assert(GSTATE.initialized);

    runWorker(getWorker(0));

    LOGF("Unexpected: main loop joined");

    for (size_t i = 1; i < WORKERS_COUNT; i++)
    {
        threadJoin(getWorker(i)->thread);
    }
    LOGF("Unexpected: other loops joined");
    exit(1);
}
