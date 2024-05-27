#pragma once
#include "api.h"
#include "idle_table.h"

struct connect_arg
{
    uint8_t      tid;
    unsigned int delay;
    tunnel_t    *t;
};

typedef struct reverse_client_con_state_s
{
    bool    pair_connected;
    bool    established;
    bool    handshaked;
    bool    first_sent_d;
    line_t *u;
    line_t *d;

} reverse_client_con_state_t;

typedef struct reverse_client_state_s
{
    idle_table_t *starved_connections;
    tunnel_t     *self;
    atomic_uint   reverse_cons;
    atomic_uint   round_index;
    uint8_t       chain_index_d;
    unsigned int  min_unused_cons;

    unsigned int unused_cons[];

} reverse_client_state_t;
