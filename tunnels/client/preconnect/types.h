#pragma once
#include "api.h"
#include "buffer_stream.h"
#include "hv/hatomic.h"

struct connect_arg
{
    unsigned int tid;
    tunnel_t *t;
};
typedef enum
{
    notconnected,
    connected_direct,
    connected_pair
} connection_state;

typedef struct preconnect_client_con_state_s
{
    struct preconnect_client_con_state_s *prev, *next;
    line_t *u;
    line_t *d;
    connection_state mode;

} preconnect_client_con_state_t;

typedef struct thread_box_s
{
    size_t length;
    preconnect_client_con_state_t root;

} thread_box_t;

typedef struct preconnect_client_state_s
{
    atomic_uint active_cons;
    atomic_uint unused_cons;

    atomic_uint round_index;
    size_t connection_per_thread;

    // settings
    int min_unused_cons;
    thread_box_t workers[];

} preconnect_client_state_t;
