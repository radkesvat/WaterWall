#pragma once
#include "api.h"
#include "buffer_stream.h"
#include "hv/hatomic.h"

struct connect_arg
{
    uint8_t      tid;
    unsigned int delay;
    tunnel_t *   t;
};

typedef struct reverse_client_con_state_s
{
    bool    pair_connected;
    bool    established;
    bool    first_sent_u;
    bool    first_sent_d;
    line_t *u;
    line_t *d;

} reverse_client_con_state_t;

typedef struct reverse_client_state_s
{
    atomic_uint  reverse_cons;
    atomic_uint  round_index;
    size_t       chain_index_pi;
    size_t       connection_per_thread;
    int          min_unused_cons;
    unsigned int unused_cons[];

} reverse_client_state_t;
