#pragma once
#include "api.h"

// enable profile to see how much it takes to connect and downstream write
// #define PROFILE 1

enum udp_connector_dynamic_value_status
{
    kCdvsEmpty = 0x0,
    kCdvsConstant,
    kCdvsFromSource,
    kCdvsFromDest,
};

typedef struct udp_connector_state_s
{
    // settings
    bool             reuse_addr;
    int              domain_strategy;
    dynamic_value_t  dest_addr_selected;
    dynamic_value_t  dest_port_selected;
    socket_context_t constant_dest_addr;

} udp_connector_state_t;

typedef struct udp_connector_con_state_s
{
#ifdef PROFILE
    struct timeval __profile_conenct;
#endif

    tunnel_t *     tunnel;
    line_t *       line;
    wio_t *        io;
    buffer_pool_t *buffer_pool;

    bool established;
} udp_connector_con_state_t;
