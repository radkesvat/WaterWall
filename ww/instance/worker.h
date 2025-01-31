#pragma once

#include "generic_pool.h"
#include "wlibc.h"
#include "wloop.h"
#include "wthread.h"


typedef uint8_t wid_t;

typedef struct worker_s
{
    wloop_t        *loop;
    buffer_pool_t  *buffer_pool;
    generic_pool_t *context_pool;
    generic_pool_t *pipetunnel_msg_pool;
    wthread_t       thread;
    wid_t           wid;

} worker_t;

extern _Thread_local wid_t tl_wid;

void workerInit(worker_t *worker, wid_t tid);
void workerRun(worker_t *worker);
void workerRunNewThread(worker_t *worker);

static inline wid_t getWID(void){
    return tl_wid;
}
