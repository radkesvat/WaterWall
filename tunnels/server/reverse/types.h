#pragma once
#include "api.h"
#include "buffer_stream.h"
#include "hatomic.h"
#include "shiftbuffer.h"

typedef struct reverse_server_con_state_s
{
    struct reverse_server_con_state_s *prev, *next;

    buffer_stream_t *wait_stream;
    context_queue_t *uqueue;
    line_t          *u;
    line_t          *d;
    bool             paired;
    bool             handshaked;
} reverse_server_con_state_t;

typedef struct thread_box_s
{
    size_t                     d_count;
    size_t                     u_count;
    reverse_server_con_state_t d_cons_root;
    reverse_server_con_state_t u_cons_root;

} thread_box_t;

typedef struct reverse_server_state_s
{

    uint8_t      chain_index_u;
    uint8_t      chain_index_d;
    thread_box_t threadlocal_pool[];

} reverse_server_state_t;
