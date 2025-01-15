#include "worker.h"
#include "frand.h"
#include "wloop.h"
#include "wthread.h"
#include "loggers/core_logger.h"
#include "loggers/dns_logger.h"
#include "loggers/network_logger.h"
#include "loggers/internal_logger.h"

#include "managers/node_manager.h"
#include "managers/signal_manager.h"
#include "managers/socket_manager.h"
#include "pipe_line.h"
#include "utils/stringutils.h"



static void initalizeWorker(worker_t *worker, tid_t tid)
{
    *worker = (worker_t){.tid = tid};

    worker->context_pool      = newGenericPoolWithCap(GSTATE.masterpool_context_pools, (16) + GSTATE.ram_profile,
                                                      allocContextPoolHandle, destroyContextPoolHandle);
    worker->line_pool         = newGenericPoolWithCap(GSTATE.masterpool_line_pools, (8) + GSTATE.ram_profile,
                                                      allocLinePoolHandle, destroyLinePoolHandle);
    worker->pipeline_msg_pool = newGenericPoolWithCap(GSTATE.masterpool_pipeline_msg_pools, (8) + GSTATE.ram_profile,
                                                      allocPipeLineMsgPoolHandle, destroyPipeLineMsgPoolHandle);
    worker->buffer_pool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small,
                                           (0) + GSTATE.ram_profile);

    // note that loop depeneds on worker->buffer_pool
    worker->loop = wloopCreate(WLOOP_FLAG_AUTO_FREE, worker->buffer_pool, tid);

    GSTATE.shortcut_context_pools[tid]      = worker->context_pool;
    GSTATE.shortcut_line_pools[tid]         = worker->line_pool;
    GSTATE.shortcut_pipeline_msg_pools[tid] = worker->pipeline_msg_pool;
    GSTATE.shortcut_buffer_pools[tid]       = worker->buffer_pool;
    GSTATE.shortcut_loops[tid]              = worker->loop;
}

static void runWorker(worker_t *worker)
{
    frandInit();
    wloopRun(worker->loop);
    wloopDestroy(&worker->loop);
}



static HTHREAD_ROUTINE(worker_thread) // NOLINT
{
    worker_t *worker = userdata;

    runWorker(worker);

    return 0;
}


