#include "ww.h"
#include "hloop.h"
#include "hthread.h"
#include "loggers/core_logger.h"
#include "loggers/dns_logger.h"
#include "loggers/network_logger.h"
#include "managers/memory_manager.h"
#include "managers/node_manager.h"
#include "managers/signal_manager.h"
#include "managers/socket_manager.h"
#include "pipe_line.h"
#include "utils/stringutils.h"

ww_global_state_t global_ww_state = {0};

void setWW(struct ww_global_state_s *state)
{
    assert(! GSTATE.initialized && state->initialized);
    GSTATE = *state;

    setCoreLogger(GSTATE.core_logger);
    setNetworkLogger(GSTATE.network_logger);
    setDnsLogger(GSTATE.dns_logger);
    setSignalManager(GSTATE.signal_manager);
    setSocketManager(GSTATE.socekt_manager);
    setNodeManager(GSTATE.node_manager);
}

struct ww_global_state_s *getWW(void)
{
    return &(GSTATE);
}

static void initalizeWorker(worker_t *worker, tid_t tid)
{
    *worker = (worker_t) {.tid = tid};

    worker->context_pool = newGenericPoolWithCap(GSTATE.masterpool_context_pools, (16) + GSTATE.ram_profile,
                                                 allocContextPoolHandle, destroyContextPoolHandle);
    GSTATE.shortcut_context_pools[tid] = getWorker(tid)->context_pool;

    worker->line_pool               = newGenericPoolWithCap(GSTATE.masterpool_line_pools, (8) + GSTATE.ram_profile,
                                                            allocLinePoolHandle, destroyLinePoolHandle);
    GSTATE.shortcut_line_pools[tid] = getWorker(tid)->line_pool;

    worker->pipeline_msg_pool = newGenericPoolWithCap(GSTATE.masterpool_pipeline_msg_pools, (8) + GSTATE.ram_profile,
                                                      allocPipeLineMsgPoolHandle, destroyPipeLineMsgPoolHandle);
    GSTATE.shortcut_pipeline_msg_pools[tid] = getWorker(tid)->pipeline_msg_pool;

    worker->shift_buffer_pool = newGenericPoolWithCap(GSTATE.masterpool_shift_buffer_pools, (64) + GSTATE.ram_profile,
                                                      allocShiftBufferPoolHandle, destroyShiftBufferPoolHandle);
    GSTATE.shortcut_shift_buffer_pools[tid] = getWorker(tid)->shift_buffer_pool;

    worker->buffer_pool = createBufferPool(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small,
                                           worker->shift_buffer_pool);
    GSTATE.shortcut_buffer_pools[tid] = getWorker(tid)->buffer_pool;

    worker->loop               = hloop_new(HLOOP_FLAG_AUTO_FREE, worker->buffer_pool, 0);
    GSTATE.shortcut_loops[tid] = getWorker(tid)->loop;
}

static void runWorker(worker_t *worker)
{
    hloop_run(worker->loop);
    hloop_free(&worker->loop);
}

_Noreturn void runMainThread(void)
{
    assert(GSTATE.initialized);

    runWorker(getWorker(0));

    LOGF("Unexpected: main loop joined");

    for (size_t i = 1; i < WORKERS_COUNT; i++)
    {
        hthread_join(getWorker(i)->thread);
    }
    LOGF("Unexpected: other loops joined");
    exit(1);
}

static HTHREAD_ROUTINE(worker_thread) // NOLINT
{
    worker_t *worker = userdata;

    runWorker(worker);

    return 0;
}

void initHeap(void)
{
    // [Section] custom malloc/free setup (global heap)
    initMemoryManager();
}

static void initializeShortCuts(void)
{
    assert(GSTATE.initialized);

    static const int kShourtcutsCount = 6;
    const int        total_workers    = WORKERS_COUNT;

    void **space = globalMalloc(sizeof(void *) * kShourtcutsCount * total_workers);

    GSTATE.shortcut_loops              = (hloop_t **) (space + (0UL * total_workers));
    GSTATE.shortcut_buffer_pools       = (buffer_pool_t **) (space + (1UL * total_workers));
    GSTATE.shortcut_shift_buffer_pools = (generic_pool_t **) (space + (2UL * total_workers));
    GSTATE.shortcut_context_pools      = (generic_pool_t **) (space + (3UL * total_workers));
    GSTATE.shortcut_line_pools         = (generic_pool_t **) (space + (4UL * total_workers));
    GSTATE.shortcut_pipeline_msg_pools = (generic_pool_t **) (space + (5UL * total_workers));
}

static void initializeMasterPools(void)
{
    assert(GSTATE.initialized);

    GSTATE.masterpool_shift_buffer_pools = newMasterPoolWithCap(2 * ((64) + GSTATE.ram_profile));
    GSTATE.masterpool_buffer_pools_large = newMasterPoolWithCap(2 * ((0) + GSTATE.ram_profile));
    GSTATE.masterpool_buffer_pools_small = newMasterPoolWithCap(2 * ((0) + GSTATE.ram_profile));
    GSTATE.masterpool_context_pools      = newMasterPoolWithCap(2 * ((16) + GSTATE.ram_profile));
    GSTATE.masterpool_line_pools         = newMasterPoolWithCap(2 * ((8) + GSTATE.ram_profile));
    GSTATE.masterpool_pipeline_msg_pools = newMasterPoolWithCap(2 * ((8) + GSTATE.ram_profile));
}

void createWW(const ww_construction_data_t init_data)
{
    GSTATE.initialized = true;

    // [Section] loggers
    {
        if (init_data.core_logger_data.log_file_path)
        {
            GSTATE.core_logger =
                createCoreLogger(init_data.core_logger_data.log_file_path, init_data.core_logger_data.log_console);

            toUpperCase(init_data.core_logger_data.log_level);
            setCoreLoggerLevelByStr(init_data.core_logger_data.log_level);
        }
        if (init_data.network_logger_data.log_file_path)
        {
            GSTATE.network_logger = createNetworkLogger(init_data.network_logger_data.log_file_path,
                                                        init_data.network_logger_data.log_console);

            toUpperCase(init_data.network_logger_data.log_level);
            setNetworkLoggerLevelByStr(init_data.network_logger_data.log_level);

            // libhv has a separate logger, attach it to the network logger
            logger_set_level_by_str(hv_default_logger(), init_data.network_logger_data.log_level);
            logger_set_handler(hv_default_logger(), getNetworkLoggerHandle());
        }
        if (init_data.dns_logger_data.log_file_path)
        {
            GSTATE.dns_logger =
                createDnsLogger(init_data.dns_logger_data.log_file_path, init_data.dns_logger_data.log_console);

            toUpperCase(init_data.dns_logger_data.log_level);
            setDnsLoggerLevelByStr(init_data.dns_logger_data.log_level);
        }
    }

    // [Section] workers and pools creation
    {
        WORKERS_COUNT      = init_data.workers_count;
        GSTATE.ram_profile = init_data.ram_profile;

        if (WORKERS_COUNT <= 0 || WORKERS_COUNT > (255))
        {
            fprintf(stderr, "workers count was not in valid range, value: %u range:[1 - %d]\n", WORKERS_COUNT, (255));
            WORKERS_COUNT = (255);
        }

        WORKERS = (worker_t *) globalMalloc(sizeof(worker_t) * (WORKERS_COUNT));

        initializeShortCuts();
        initializeMasterPools();

        for (unsigned int i = 0; i < WORKERS_COUNT; ++i)
        {
            initalizeWorker(getWorker(i), i);
        }
    }

    // [Section] setup SignalManager
    {
        GSTATE.signal_manager = createSignalManager();
        startSignalManager();
    }
    // [Section] setup SocketMangager
    {
        GSTATE.socekt_manager = createSocketManager();
    }

    // [Section] setup NodeManager
    {
        GSTATE.node_manager = createNodeManager();
    }

    // [Section] Spawn all workers except main worker which is current thread
    {
        WORKERS[0].thread = (hthread_t) NULL;
        for (unsigned int i = 1; i < WORKERS_COUNT; ++i)
        {
            WORKERS[i].thread = hthread_create(worker_thread, getWorker(i));
        }
    }
}
