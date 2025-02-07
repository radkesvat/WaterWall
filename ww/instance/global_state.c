#include "global_state.h"
#include "buffer_pool.h"
#include "crypto/openssl_instance.h"
#include "crypto/sodium_instance.h"
#include "loggers/core_logger.h"
#include "loggers/dns_logger.h"
#include "loggers/internal_logger.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "managers/signal_manager.h"
#include "managers/socket_manager.h"

ww_global_state_t global_ww_state = {0};

ww_global_state_t *globalStateGet(void)
{
    return &GSTATE;
}

void globalStateSet(struct ww_global_state_s *state)
{
    assert(! GSTATE.flag_initialized && state->flag_initialized);
    GSTATE = *state;

    setCoreLogger(GSTATE.core_logger);
    setNetworkLogger(GSTATE.network_logger);
    setDnsLogger(GSTATE.dns_logger);
    setInternalLogger(GSTATE.internal_logger);
    setSignalManager(GSTATE.signal_manager);
    socketmanagerSet(GSTATE.socekt_manager);
    nodemanagerSetState(GSTATE.node_manager);
}

void globalstateUpdaeAllocationPadding(uint16_t padding)
{
    for (int wi = 0; wi < getWorkersCount(); wi++)
    {
        bufferpoolUpdateAllocationPaddings(getWorkerBufferPool(wi), padding, padding);
    }
    GSTATE.flag_buffers_calculated = true;
}

static void initializeShortCuts(void)
{
    assert(GSTATE.flag_initialized);

    static const int kShourtcutsCount = 5;

    const int total_workers = WORKERS_COUNT;

    void **space = (void **) memoryAllocate(sizeof(void *) * kShourtcutsCount * total_workers);

    GSTATE.shortcut_loops                = (wloop_t **) (space + (0ULL * total_workers));
    GSTATE.shortcut_buffer_pools         = (buffer_pool_t **) (space + (1ULL * total_workers));
    GSTATE.shortcut_context_pools        = (generic_pool_t **) (space + (2ULL * total_workers));
    GSTATE.shortcut_pipetunnel_msg_pools = (generic_pool_t **) (space + (3ULL * total_workers));

    for (unsigned int tid = 0; tid < GSTATE.workers_count; tid++)
    {

        GSTATE.shortcut_context_pools[tid]        = WORKERS[tid].context_pool;
        GSTATE.shortcut_pipetunnel_msg_pools[tid] = WORKERS[tid].pipetunnel_msg_pool;
        GSTATE.shortcut_buffer_pools[tid]         = WORKERS[tid].buffer_pool;
        GSTATE.shortcut_loops[tid]                = WORKERS[tid].loop;
    }
}

static void initializeMasterPools(void)
{
    assert(GSTATE.flag_initialized);

    GSTATE.masterpool_buffer_pools_large   = masterpoolCreateWithCapacity(2 * ((0) + GSTATE.ram_profile));
    GSTATE.masterpool_buffer_pools_small   = masterpoolCreateWithCapacity(2 * ((0) + GSTATE.ram_profile));
    GSTATE.masterpool_context_pools        = masterpoolCreateWithCapacity(2 * ((16) + GSTATE.ram_profile));
    GSTATE.masterpool_pipetunnel_msg_pools = masterpoolCreateWithCapacity(2 * ((8) + GSTATE.ram_profile));
}

void createGlobalState(const ww_construction_data_t init_data)
{
    GSTATE.flag_initialized = true;

    // [Section] loggers
    {
        GSTATE.internal_logger = createInternalLogger(init_data.internal_logger_data.log_file_path,
                                                      init_data.internal_logger_data.log_console);
        stringUpperCase(init_data.internal_logger_data.log_level);
        setInternalLoggerLevelByStr(init_data.internal_logger_data.log_level);

        GSTATE.core_logger =
            createCoreLogger(init_data.core_logger_data.log_file_path, init_data.core_logger_data.log_console);

        stringUpperCase(init_data.core_logger_data.log_level);
        setCoreLoggerLevelByStr(init_data.core_logger_data.log_level);

        GSTATE.network_logger =
            createNetworkLogger(init_data.network_logger_data.log_file_path, init_data.network_logger_data.log_console);

        stringUpperCase(init_data.network_logger_data.log_level);
        setNetworkLoggerLevelByStr(init_data.network_logger_data.log_level);

        GSTATE.dns_logger =
            createDnsLogger(init_data.dns_logger_data.log_file_path, init_data.dns_logger_data.log_console);

        stringUpperCase(init_data.dns_logger_data.log_level);
        setDnsLoggerLevelByStr(init_data.dns_logger_data.log_level);
    }

    // workers and pools creation
    {
        WORKERS_COUNT      = init_data.workers_count;
        GSTATE.ram_profile = init_data.ram_profile;

        // this check was required to avoid overflow in older version when workers_count was limited to 254
        if (WORKERS_COUNT <= 0 || WORKERS_COUNT > (255))
        {
            LOGW("workers count was not in valid range, value: %u range:[1 - %d]\n", WORKERS_COUNT, (255));
            WORKERS_COUNT = (255);
        }

        WORKERS = (worker_t *) memoryAllocate(sizeof(worker_t) * (WORKERS_COUNT));

        initializeMasterPools();

        for (unsigned int i = 0; i < WORKERS_COUNT; ++i)
        {
            workerInit(getWorker(i), i);
        }

        initializeShortCuts();
    }

    // managers
    {
        GSTATE.signal_manager = createSignalManager();
        GSTATE.socekt_manager = socketmanagerCreate();
        GSTATE.node_manager   = nodemanagerCreate();
    }

    // SSL
    {
        opensslGlobalInit();
        GSTATE.flag_libsodium_initialized = initSodium();
        if (! (GSTATE.flag_libsodium_initialized))
        {
            printError("Failed to initialize libsodium\n");
            exit(1);
        }
    }
    // Spawn all workers except main worker which is current thread
    {
        for (unsigned int i = 1; i < WORKERS_COUNT; ++i)
        {
            workerRunNewThread(&WORKERS[i]);
        }
    }

    startSignalManager();
}

void runMainThread(void)
{
    assert(GSTATE.flag_initialized);

    WORKERS[0].thread = (wthread_t) NULL;
    workerRun(getWorker(0));

    LOGF("Unexpected: main loop joined");

    for (size_t i = 1; i < WORKERS_COUNT; i++)
    {
        threadJoin(getWorker(i)->thread);
    }
    LOGF("Unexpected: other loops joined");
    exit(1);
}
