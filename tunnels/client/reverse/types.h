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
    idle_item_t *idle_handle;
    line_t      *u;
    line_t      *d;
    tunnel_t    *self;

} reverse_client_con_state_t;

typedef struct thread_box_s
{
    uint32_t unused_cons_count;
    uint32_t connecting_cons_count;

} thread_box_t;

typedef struct reverse_client_state_s
{
    idle_table_t *starved_connections;
    atomic_uint   reverse_cons;
    atomic_uint   round_index;
    unsigned int  min_unused_cons;

    thread_box_t threadlocal_pool[];

} reverse_client_state_t;
