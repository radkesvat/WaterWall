#pragma once
#include "api.h"

#define STATE(x)      ((connector_state_t *) ((x)->state))
#define CSTATE(x)     ((connector_con_state_t *) ((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]

// enable profile to see how much it takes to connect and downstream write, dns and etc...
// #define PROFILE 1

enum connector_dynamic_value_status
{
    kCdvsEmpty = 0x0,
    kCdvsConstant,
    kCdvsFromSource,
    kCdvsFromDest,
};

typedef struct connector_state_s
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

} connector_state_t;

typedef struct connector_con_state_s
{
#ifdef PROFILE
    struct timeval __profile_conenct;
#endif
    TunnelFlowRoutine upstream;
    TunnelFlowRoutine downstream;
    tunnel_t *        tunnel;
    line_t *          line;
    hio_t *           io;

    buffer_pool_t *  buffer_pool;
    context_queue_t *data_queue;
    context_queue_t *finished_queue;

    bool write_paused;
    bool established;
} connector_con_state_t;

bool connectorResolvedomain(socket_context_t *dest);

void connectorTcpUpStream(tunnel_t *self, context_t *c);
void connectorTcpDownStream(tunnel_t *self, context_t *c);

void connectorPacketUpStream(tunnel_t *self, context_t *c);
void connectorPacketDownStream(tunnel_t *self, context_t *c);
