#pragma once
#include "api.h"
#include "loggers/dns_logger.h"
#include "loggers/network_logger.h"

#define STATE(x) ((tcp_connector_state_t *)((x)->state))
#define CSTATE(x) ((tcp_connector_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]


// enable profile to see how much it takes to connect and downstream write
// #define PROFILE 1

enum tcp_connector_dynamic_value_status
{
    cdvs_empty = 0x0,
    cdvs_constant,
    cdvs_from_source,
    cdvs_from_dest,
};

typedef struct tcp_connector_state_s
{
    // settings
    bool tcp_no_delay;
    bool tcp_fast_open; 
    bool reuse_addr;
    enum domain_strategy domain_strategy;

    size_t dest_domain_len;
    enum socket_address_type dest_atype;
    dynamic_value_t dest_addr;
    dynamic_value_t dest_port;

} tcp_connector_state_t;

typedef struct tcp_connector_con_state_s
{
#ifdef PROFILE
    struct timeval __profile_conenct;
#endif

    tunnel_t *tunnel;
    line_t *line;
    hio_t *io;
    hio_t *io_back;

    buffer_pool_t *buffer_pool;
    context_queue_t *queue;
    context_t *current_w;

    bool write_paused;
    bool established;
} tcp_connector_con_state_t;



bool tcpConnectorResolvedomain(socket_context_t *dest);




