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

    // additional therad 1 : socket manager

*/
enum
{
    kAdditionalReservedWorkers = 1,
    kUnInitializedTid          = 0x10000U
};

ww_global_state_t global_ww_state = {0};

void setWW(struct ww_global_state_s *state)
{

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

atomic_uint last_thread_id;

static void initalizeWorker(tid_t tid)
{
    worker_t *worker = &(WORKERS[tid]);

    worker->tid = tid;
    worker->shift_buffer_pool =
        newGenericPoolWithCap((64) + GSTATE.ram_profile, allocShiftBufferPoolHandle, destroyShiftBufferPoolHandle);

    worker->buffer_pool = createBufferPool(tid);

    worker->loop = hloop_new(HLOOP_FLAG_AUTO_FREE, worker->buffer_pool, 0);

    worker->context_pool =
        newGenericPoolWithCap((16) + GSTATE.ram_profile, allocContextPoolHandle, destroyContextPoolHandle);

    worker->line_pool = newGenericPoolWithCap((8) + GSTATE.ram_profile, allocLinePoolHandle, destroyLinePoolHandle);

    worker->pipeline_msg_pool =
        newGenericPoolWithCap((8) + GSTATE.ram_profile, allocPipeLineMsgPoolHandle, destroyPipeLineMsgPoolHandle);
}

static void runWorker(tid_t tid)
{
    worker_t *worker = &(WORKERS[tid]);

    hloop_run(worker->loop);
    hloop_free(&worker->loop);
}

_Noreturn void runMainThread(void)
{
    runWorker(0);
    LOGF("Unexpected: main loop joined");

    for (size_t i = 1; i < WORKERS_COUNT; i++)
    {
        hthread_join(WORKERS[i].thread);
    }
    LOGF("Unexpected: other loops joined");
    exit(1);
}

static HTHREAD_ROUTINE(worker_thread) // NOLINT
{
    (void) userdata;

    tid_t worker_tid = (tid_t) atomic_fetch_add(&(last_thread_id), 1);
    runWorker(worker_tid);

    return 0;
}

void initHeap(void)
{
    // [Section] custom malloc/free setup (global heap)
    initMemoryManager();
}

void createWW(const ww_construction_data_t init_data)
{

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

            // libhv has a separate logger,  attach it to the network logger
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

    // [Section] workers and pools heap allocation
    {
        WORKERS_COUNT = init_data.workers_count;
        GSTATE.ram_profile   = init_data.ram_profile;

        if (WORKERS_COUNT <= 0 || WORKERS_COUNT > (255 - kAdditionalReservedWorkers))
        {
            fprintf(stderr, "workers count was not in valid range, value: %u range:[1 - 255]\n", WORKERS_COUNT);
        }

        WORKERS = (worker_t *) malloc(sizeof(worker_t) * (WORKERS_COUNT + kAdditionalReservedWorkers));

        atomic_store(&last_thread_id, 1);

        for (unsigned int i = 0; i < WORKERS_COUNT; ++i)
        {
            initalizeWorker(i);
            // WORKERS[i].thread = hthread_create(worker_thread, NULL);
        }
    }

    // [Section] setup SocketMangager thread, note that we use smaller buffer pool here
    {

        tid_t accept_thread_tid = (tid_t) atomic_fetch_add(&(last_thread_id), 1);

        worker_t *worker = &(WORKERS[accept_thread_tid]);

        worker->tid = accept_thread_tid;
        worker->shift_buffer_pool =
            newGenericPoolWithCap((64) + GSTATE.ram_profile, allocShiftBufferPoolHandle, destroyShiftBufferPoolHandle);

        worker->buffer_pool = createSmallBufferPool(accept_thread_tid);

        worker->loop = hloop_new(HLOOP_FLAG_AUTO_FREE, worker->buffer_pool, 0);

        GSTATE.socekt_manager = createSocketManager(worker->loop, worker->tid);
    }

    // [Section] setup NodeManager
    {
        GSTATE.node_manager = createNodeManager();
    }

    WORKERS[0].thread = (hthread_t)NULL;
    // [Section] Spawn all workers expect main worker which is current thread
    for (unsigned int i = 1; i < WORKERS_COUNT; ++i)
    {
        WORKERS[i].thread = hthread_create(worker_thread, NULL);
    }
}
