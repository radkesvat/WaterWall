#pragma once

#include "wwapi.h"

typedef struct tcpconnector_tstate_s
{
    widle_table_t *idle_table; // idle table for closing dead connections

    // These options are read form the json configuration
    dynamic_value_t dest_addr_selected;   // dynamic value for destination address
    dynamic_value_t dest_port_selected;   // dynamic value for destination port
    bool            option_tcp_no_delay;  // apply TCP no delay option on sockets
    bool            option_tcp_fast_open; // apply TCP fast open option on sockets
    bool            option_reuse_addr;    // apply reuse address option on sockets
    int             domain_strategy;      // prefer ipv4 or ipv6
    int             fwmark;               // firewall mark on linux (beta)
    uint64_t        outbound_ip_range;    // range for outbound ip (this means free bind)

    // These options are evaluatde at start
    // constant destination address to avoid copy, can contain the domain name, used if possible
    address_context_t constant_dest_addr;
} tcpconnector_tstate_t;

typedef struct tcpconnector_lstate_s
{
    tunnel_t     *tunnel;      // reference to the tunnel (TcpConnector)
    line_t       *line;        // reference to the line
    wio_t        *io;          // IO handle for the connection (socket)
    widle_item_t *idle_handle; // reference to the idle item for this connection
    // These fields are used internally for the queue implementation for TCP
    buffer_queue_t pause_queue;
    buffer_pool_t *buffer_pool;
    bool           write_paused : 1;
    bool           read_paused : 1;

} tcpconnector_lstate_t;

enum
{
    kTunnelStateSize    = sizeof(tcpconnector_tstate_t),
    kLineStateSize      = sizeof(tcpconnector_lstate_t),
    kMaxPauseQueueSize  = 1024 * 1024, // 1MB
    kReadWriteTimeoutMs = 300 * 1000,
    kPauseQueueCapacity = 2
};

typedef enum tcpconnector_strategy
{
    kTcpConnectorStrategyRandom = 0,
    kTcpConnectorStrategyConstant,
    kTcpConnectorStrategyFromSource,
    kTcpConnectorStrategyFromDest
} tcpconnector_strategy_e;

enum
{
    kFwMarkInvalid = -1
};

WW_EXPORT void         tcpconnectorTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *tcpconnectorTunnelCreate(node_t *node);
WW_EXPORT api_result_t tcpconnectorTunnelApi(tunnel_t *instance, sbuf_t *message);

void tcpconnectorTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void tcpconnectorTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void tcpconnectorTunnelOnPrepair(tunnel_t *t);
void tcpconnectorTunnelOnStart(tunnel_t *t);

void tcpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l);
void tcpconnectorTunnelUpStreamEst(tunnel_t *t, line_t *l);
void tcpconnectorTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void tcpconnectorTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tcpconnectorTunnelUpStreamPause(tunnel_t *t, line_t *l);
void tcpconnectorTunnelUpStreamResume(tunnel_t *t, line_t *l);

void tcpconnectorTunnelDownStreamInit(tunnel_t *t, line_t *l);
void tcpconnectorTunnelDownStreamEst(tunnel_t *t, line_t *l);
void tcpconnectorTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void tcpconnectorTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tcpconnectorTunnelDownStreamPause(tunnel_t *t, line_t *l);
void tcpconnectorTunnelDownStreamResume(tunnel_t *t, line_t *l);

void tcpconnectorLinestateInitialize(tcpconnector_lstate_t *ls);
void tcpconnectorLinestateDestroy(tcpconnector_lstate_t *ls);

bool tcpconnectorApplyFreeBindRandomDestIp(tunnel_t *self, address_context_t *dest_ctx);
void tcpconnectorFlushWriteQueue(tcpconnector_lstate_t *lstate);
void tcpconnectorOnOutBoundConnected(wio_t *upstream_io);
void tcpconnectorOnWriteComplete(wio_t *io);
void tcpconnectorOnClose(wio_t *io);
void tcpconnectorOnIdleConnectionExpire(widle_item_t *idle_tcp);
