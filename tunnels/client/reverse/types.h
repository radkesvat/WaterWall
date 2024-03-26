#pragma once
#include "api.h"
#include "buffer_stream.h"
#include "hv/hatomic.h"

struct connect_arg
{
    unsigned int tid;
    tunnel_t *t;
};

typedef struct reverse_client_con_state_s
{
    bool pair_connected;
    bool established;
    bool first_sent;
    line_t *u;
    line_t *d;

} reverse_client_con_state_t;

typedef struct reverse_client_state_s
{
    _Atomic unsigned int reverse_cons;
    _Atomic unsigned int unused_cons;
    _Atomic unsigned int round_index;

    size_t chain_index_pi;
    size_t connection_per_thread;

    // settings
    int max_cons;

} reverse_client_state_t;
