#pragma once

#include "wlibc.h"
#include "wthread.h"


typedef uint8_t tid_t;

typedef struct worker_s
{
    wthread_t              thread;
    struct wloop_s        *loop;
    struct buffer_pool_s  *buffer_pool;
    struct generic_pool_s *context_pool;
    struct generic_pool_s *line_pool;
    struct generic_pool_s *pipeline_msg_pool;
    tid_t                  tid;

} worker_t;


static void initalizeWorker(worker_t *worker, tid_t tid)
static void runWorker(worker_t *worker)
