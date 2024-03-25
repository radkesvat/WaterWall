#pragma once

#include "api.h"
#include "buffer_stream.h"
#include "hv/hatomic.h"

typedef struct send_payloads
{
    tunnel_t* tunnel;
    
} send_target_s;



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
    _Atomic size_t d_count;
    qcons d_cons;
    _Atomic size_t u_count;
    qcons u_cons;

} thread_box_t;

typedef struct reverse_server_state_s
{
    _Atomic size_t u_available;
    _Atomic size_t d_available;

    size_t chain_index_u;
    size_t chain_index_d;

    thread_box_t threads[];

} reverse_server_state_t;
