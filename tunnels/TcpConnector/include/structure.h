#pragma once

#include "wwapi.h"

typedef struct tcpconnector_tstate_s
{
    // These options are read form the json configuration
    dynamic_value_t      dest_addr_selected;   // dynamic value for destination address
    dynamic_value_t      dest_port_selected;   // dynamic value for destination port
    bool                 option_tcp_no_delay;  // apply TCP no delay option on sockets
    bool                 option_tcp_fast_open; // apply TCP fast open option on sockets
    bool                 option_reuse_addr;    // apply reuse address option on sockets
    int                  domain_strategy;      // prefer ipv4 or ipv6
    int                  fwmark;               // firewall mark on linux (beta)
    uint64_t             outbound_ip_range;    // range for outbound ip (this means free bind)

    // These options are evaluatde at start
    // constant destination address to avoid copy, can contain the domain name, used if possible
    connection_context_t constant_dest_addr;    
} tcpconnector_tstate_t;

typedef struct tcpconnector_lstate_s
{
    tunnel_t *tunnel; // reference to the tunnel (TcpListener)
    line_t   *line;   // reference to the line
    wio_t    *io;     // IO handle for the connection (socket)
    // These fields are used internally for the queue implementation for TCP
    buffer_queue_t *data_queue;
    buffer_pool_t  *buffer_pool;
    bool            write_paused;
    bool            read_paused;
    // this flag is set when the connection is established (est recevied from upstream)
    bool established;
} tcpconnector_lstate_t;

enum
{
    kTunnelStateSize = sizeof(tcpconnector_tstate_t),
    kLineStateSize   = sizeof(tcpconnector_lstate_t)
};

enum tcpconnector_port_strategy
{
    kTcpConnectorPortStrategyRandom = 0,
    kTcpConnectorPortStrategyConstant,
    kTcpConnectorPortStrategyFromSource,
    kTcpConnectorPortStrategyFromDest
};

enum
{
    kFwMarkInvalid = -1
};

WW_EXPORT void         tcpconnectorTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *tcpconnectorTunnelCreate(node_t *node);
WW_EXPORT api_result_t tcpconnectorTunnelApi(tunnel_t *instance, sbuf_t *message);

WW_EXPORT void tcpconnectorTunnelOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
WW_EXPORT void tcpconnectorTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
WW_EXPORT void tcpconnectorTunnelOnPrepair(tunnel_t *t);
WW_EXPORT void tcpconnectorTunnelOnStart(tunnel_t *t);

WW_EXPORT void tcpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l);
WW_EXPORT void tcpconnectorTunnelUpStreamEst(tunnel_t *t, line_t *l);
WW_EXPORT void tcpconnectorTunnelUpStreamFinish(tunnel_t *t, line_t *l);
WW_EXPORT void tcpconnectorTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
WW_EXPORT void tcpconnectorTunnelUpStreamPause(tunnel_t *t, line_t *l);
WW_EXPORT void tcpconnectorTunnelUpStreamResume(tunnel_t *t, line_t *l);

WW_EXPORT void tcpconnectorTunnelDownStreamInit(tunnel_t *t, line_t *l);
WW_EXPORT void tcpconnectorTunnelDownStreamEst(tunnel_t *t, line_t *l);
WW_EXPORT void tcpconnectorTunnelDownStreamFinish(tunnel_t *t, line_t *l);
WW_EXPORT void tcpconnectorTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
WW_EXPORT void tcpconnectorTunnelDownStreamPause(tunnel_t *t, line_t *l);
WW_EXPORT void tcpconnectorTunnelDownStreamResume(tunnel_t *t, line_t *l);

void lineStateInitialize(tcpconnector_lstate_t *ls);
void lineStateDestroy(tcpconnector_lstate_t *ls);

bool applyFreeBindRandomDestIp(tunnel_t *self, connection_context_t *dest_ctx);
