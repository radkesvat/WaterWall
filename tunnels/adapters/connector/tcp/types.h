#pragma once
#include "api.h"

// enable profile to see how much it takes to connect and downstream write
// #define PROFILE 1

enum tcp_connector_dynamic_value_status
{
    kCdvsEmpty = 0x0,
    kCdvsConstant,
    kCdvsFromSource,
    kCdvsFromDest,
};

typedef struct tcp_connector_state_s
{
    // settings
    bool                 tcp_no_delay;
    bool                 tcp_fast_open;
    bool                 reuse_addr;
    enum domain_strategy domain_strategy;

    size_t                   dest_domain_len;
    enum socket_address_type dest_atype;
    dynamic_value_t          dest_addr;
    dynamic_value_t          dest_port;

} tcp_connector_state_t;

typedef struct tcp_connector_con_state_s
{
#ifdef PROFILE
    struct timeval __profile_conenct;
#endif

    tunnel_t *tunnel;
    line_t *  line;
    hio_t *   io;

    buffer_pool_t *  buffer_pool;
    context_queue_t *data_queue;
    context_queue_t *finished_queue;

    bool write_paused;
    bool established;
} tcp_connector_con_state_t;
