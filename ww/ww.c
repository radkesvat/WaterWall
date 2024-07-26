#include "ww.h"
#include "hloop.h"
#include "hthread.h"
#include "loggers/core_logger.h"
#include "loggers/dns_logger.h"
#include "loggers/network_logger.h"
#include "managers/memory_manager.h"
#include "managers/node_manager.h"
#include "managers/socket_manager.h"
#include "pipe_line.h"
#include "utils/stringutils.h"

/*
    additional threads that dose not require instances of every pools and they will create what they need
    so, these additions will only reserve their own space on the workers array

    the only purpose of this is to reduce memory usage

    additional therad 1 : socket manager

*/

enum
{
    kSocketManagerWorkerId     = 0,
    kAdditionalReservedWorkers = 1
};

ww_global_state_t global_ww_state = {0};

void setWW(struct ww_global_state_s *state)
{
    assert(! GSTATE.initialized && state->initialized);
    GSTATE = *state;

    setCoreLogger(GSTATE.core_logger);
    setNetworkLogger(GSTATE.network_logger);
    setDnsLogger(GSTATE.dns_logger);
    setSocketManager(GSTATE.socekt_manager);
    setNodeManager(GSTATE.node_manager);
}

struct ww_global_state_s *getWW(void)
{
    return &(GSTATE);
}

// same as regular workers except that it uses smaller buffer pools and won't allocate unused pools
static void initalizeSocketManagerWorker(worker_t *worker, tid_t tid)
{
    *worker = (worker_t) {.tid = tid};

    worker->shift_buffer_pool =
        newGenericPoolWithCap((64) + GSTATE.ram_profile, allocShiftBufferPoolHandle, destroyShiftBufferPoolHandle);

    worker->buffer_pool = createSmallBufferPool(worker->tid);

    worker->loop = hloop_new(HLOOP_FLAG_AUTO_FREE, worker->buffer_pool, 0);
}

static void initalizeWorker(worker_t *worker, tid_t tid)
{
    *worker = (worker_t) {.tid = tid};

    worker->shift_buffer_pool =
        newGenericPoolWithCap((64) + GSTATE.ram_profile, allocShiftBufferPoolHandle, destroyShiftBufferPoolHandle);

    worker->buffer_pool = createBufferPool(worker->tid);

    worker->loop = hloop_new(HLOOP_FLAG_AUTO_FREE, worker->buffer_pool, 0);

    worker->context_pool =
        newGenericPoolWithCap((16) + GSTATE.ram_profile, allocContextPoolHandle, destroyContextPoolHandle);

    worker->line_pool = newGenericPoolWithCap((8) + GSTATE.ram_profile, allocLinePoolHandle, destroyLinePoolHandle);

    worker->pipeline_msg_pool =
        newGenericPoolWithCap((8) + GSTATE.ram_profile, allocPipeLineMsgPoolHandle, destroyPipeLineMsgPoolHandle);
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

static void buildShortCuts(void)
{
    assert(GSTATE.initialized);

    tid_t workers_count = GSTATE.workers_count;

    static const int kShourtcutsCount = 6;
    const int        total_workers    = workers_count + kAdditionalReservedWorkers;

    void **space = globalMalloc(sizeof(void *) * kShourtcutsCount * total_workers);

    GSTATE.shortcut_loops              = (hloop_t **) (space + (0 * sizeof(void *) * total_workers));
    GSTATE.shortcut_buffer_pools       = (buffer_pool_t **) (space + (1 * sizeof(void *) * total_workers));
    GSTATE.shortcut_shift_buffer_pools = (generic_pool_t **) (space + (2 * sizeof(void *) * total_workers));
    GSTATE.shortcut_context_pools      = (generic_pool_t **) (space + (3 * sizeof(void *) * total_workers));
    GSTATE.shortcut_line_pools         = (generic_pool_t **) (space + (4 * sizeof(void *) * total_workers));
    GSTATE.shortcut_pipeline_msg_pools = (generic_pool_t **) (space + (5 * sizeof(void *) * total_workers));

    for (int i = 0; i < total_workers; i++)
    {
        GSTATE.shortcut_loops[i]              = (getWorker(i)->loop);
        GSTATE.shortcut_buffer_pools[i]       = (getWorker(i)->buffer_pool);
        GSTATE.shortcut_shift_buffer_pools[i] = (getWorker(i)->shift_buffer_pool);
        GSTATE.shortcut_context_pools[i]      = (getWorker(i)->context_pool);
        GSTATE.shortcut_line_pools[i]         = (getWorker(i)->line_pool);
        GSTATE.shortcut_pipeline_msg_pools[i] = (getWorker(i)->pipeline_msg_pool);
    }
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

        if (WORKERS_COUNT <= 0 || WORKERS_COUNT > (255 - kAdditionalReservedWorkers))
        {
            fprintf(stderr, "workers count was not in valid range, value: %u range:[1 - %d]\n", WORKERS_COUNT,
                    (255 - kAdditionalReservedWorkers));
            WORKERS_COUNT = (255 - kAdditionalReservedWorkers);
        }

        WORKERS = (worker_t *) malloc(sizeof(worker_t) * (WORKERS_COUNT + kAdditionalReservedWorkers));

        for (unsigned int i = 0; i < WORKERS_COUNT; ++i)
        {
            initalizeWorker(getWorker(i), i);
        }
    }

    // [Section] setup SocketMangager thread (Additional Worker 1)
    {
        tid_t     accept_thread_tid = (WORKERS_COUNT) + kSocketManagerWorkerId;
        worker_t *accept_worker     = getWorker(accept_thread_tid);

        initalizeSocketManagerWorker(accept_worker, accept_thread_tid);

        GSTATE.socekt_manager = createSocketManager(accept_worker);
    }

    // [Section] setup NodeManager
    {
        GSTATE.node_manager = createNodeManager();
    }

    buildShortCuts();

    // [Section] Spawn all workers expect main worker which is current thread
    {
        WORKERS[0].thread = (hthread_t) NULL;
        for (unsigned int i = 1; i < WORKERS_COUNT; ++i)
        {
            WORKERS[i].thread = hthread_create(worker_thread, getWorker(i));
        }
    }
}
