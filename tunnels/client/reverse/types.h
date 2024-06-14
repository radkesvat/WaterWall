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
    bool         pair_connected;
    bool         established;
    bool         first_sent_d;
    idle_item_t *idle_handle;
    line_t      *u;
    line_t      *d;
    tunnel_t    *self;

} reverse_client_con_state_t;

typedef struct reverse_client_state_s
{
    idle_table_t *starved_connections;
    atomic_uint   reverse_cons;
    atomic_uint   round_index;
    uint8_t       chain_index_d;
    unsigned int  min_unused_cons;

    unsigned int unused_cons[];

} reverse_client_state_t;
