#pragma once

#include "generic_pool.h"
#include "wlibc.h"
#include "wloop.h"
#include "wthread.h"


typedef uint8_t tid_t;

typedef struct worker_s
{
    wloop_t        *loop;
    buffer_pool_t  *buffer_pool;
    generic_pool_t *context_pool;
    generic_pool_t *pipeline_msg_pool;
    wthread_t       thread;
    tid_t           tid;

} worker_t;

void workerInit(worker_t *worker, tid_t tid);
void workerRun(worker_t *worker);
void workerRunNewThread(worker_t *worker);
