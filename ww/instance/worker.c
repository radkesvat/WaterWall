#include "worker.h"
#include "context.h"
#include "global_state.h"
#include "pipe_tunnel.h"
#include "tunnel.h"
#include "wloop.h"
#include "wthread.h"



thread_local wid_t tl_wid;

void workerInit(worker_t *worker, wid_t wid)
{
    *worker = (worker_t){.wid = wid};

    worker->context_pool = genericpoolCreateWithDefaultAllocatorAndCapacity(
        GSTATE.masterpool_context_pools, sizeof(context_t), (16) + GSTATE.ram_profile);

    worker->pipetunnel_msg_pool = genericpoolCreateWithDefaultAllocatorAndCapacity(
        GSTATE.masterpool_pipetunnel_msg_pools, pipeLineGetMesageSize(), (8) + GSTATE.ram_profile);

    worker->buffer_pool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small,
                                           (0) + GSTATE.ram_profile, SMALL_BUFFER_SIZE, LARGE_BUFFER_SIZE);

    // note that loop depeneds on worker->buffer_pool
    worker->loop = wloopCreate(WLOOP_FLAG_AUTO_FREE, worker->buffer_pool, wid);
}

void workerRun(worker_t *worker)
{
    tl_wid = worker->wid;
    frandInit();
    wloopRun(worker->loop);
    wloopDestroy(&worker->loop);
}

static WTHREAD_ROUTINE(worker_thread) // NOLINT
{
    worker_t *worker = userdata;

    workerRun(worker);

    return 0;
}

void workerRunNewThread(worker_t *worker)
{
    worker->thread = threadCreate(worker_thread, worker);
}
