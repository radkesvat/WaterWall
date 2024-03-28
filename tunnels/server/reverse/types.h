#pragma once
#include "api.h"
#include "buffer_stream.h"
#include "hv/hatomic.h"

typedef struct reverse_server_con_state_s
{
    bool paired;
    bool samethread;
    context_queue_t *uqueue;

    line_t *u;
    line_t *d;

} reverse_server_con_state_t;

#define i_TYPE qcons, reverse_server_con_state_t *
#define i_use_cmp
#include "stc/queue.h"

typedef struct thread_box_s
{
    size_t d_count;
    qcons d_cons;
    size_t u_count;
    qcons u_cons;

} thread_box_t;

typedef struct reverse_server_state_s
{
    atomic_size_t u_available;
    atomic_size_t d_available;

    size_t chain_index_u;
    size_t chain_index_d;

    thread_box_t threads[];

} reverse_server_state_t;
