#include "worker.h"
#include "wloop.h"
#include "wthread.h"
#include "global_state.h"
#include "tunnel.h"
#include "line.h"
#include "context.h"

#define SMALL_BUFFER_SIZE 1500
#define LARGE_BUFFER_SIZE (GSTATE.ram_profile >= kRamProfileS2Memory ? (1U << 15) : (1U << 12))

void initalizeWorker(worker_t *worker, tid_t tid)
{
    *worker = (worker_t){.tid = tid};

    worker->context_pool      = newGenericPoolWithCap(GSTATE.masterpool_context_pools, (16) + GSTATE.ram_profile,
                                                      allocContextPoolHandle, destroyContextPoolHandle);

    worker->pipeline_msg_pool = newGenericPoolWithCap(GSTATE.masterpool_pipeline_msg_pools, (8) + GSTATE.ram_profile,
                                                      allocPipeLineMsgPoolHandle, destroyPipeLineMsgPoolHandle);

    worker->buffer_pool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small,
                                           (0) + GSTATE.ram_profile, SMALL_BUFFER_SIZE, LARGE_BUFFER_SIZE);

    // note that loop depeneds on worker->buffer_pool
    worker->loop = wloopCreate(WLOOP_FLAG_AUTO_FREE, worker->buffer_pool, tid);
}

void runWorker(worker_t *worker)
{

    frandInit();
    wloopRun(worker->loop);
    wloopDestroy(&worker->loop);
}

static WTHREAD_ROUTINE(worker_thread) // NOLINT
{
    worker_t *worker = userdata;

    runWorker(worker);

    return 0;
}

void runWorkerNewThread(worker_t *worker)
{
    worker->thread = threadCreate(worker_thread, worker);
}
