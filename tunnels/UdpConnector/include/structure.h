#pragma once

#include "wwapi.h"

enum udp_connector_dynamic_value_status
{

    kDvsFromSource = kDvsFirstOption,
    kDvsFromDest,
};

typedef struct udpconnector_tstate_s
{
    bool              reuse_addr;         // whether to reuse address
    int               domain_strategy;    // DNS resolution strategy
    dynamic_value_t   dest_addr_selected; // selected destination address
    dynamic_value_t   dest_port_selected; // selected destination port
    address_context_t constant_dest_addr; // constant destination address for the connection
} udpconnector_tstate_t;

typedef struct udpconnector_lstate_s
{

    tunnel_t *tunnel;          // reference to the tunnel
    line_t   *line;            // reference to the line
    wio_t    *io;              // IO handle for the connection (socket)
    bool      read_paused : 1; // whether the read is paused
    bool      established : 1; // whether anything received to send est downstream once

} udpconnector_lstate_t;

enum
{
    kTunnelStateSize   = sizeof(udpconnector_tstate_t),
    kLineStateSize     = sizeof(udpconnector_lstate_t),
    kUdpKeepExpireTime = 60 * 1000
};

WW_EXPORT void         udpconnectorTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *udpconnectorTunnelCreate(node_t *node);
WW_EXPORT api_result_t udpconnectorTunnelApi(tunnel_t *instance, sbuf_t *message);

void udpconnectorTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void udpconnectorTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void udpconnectorTunnelOnPrepair(tunnel_t *t);
void udpconnectorTunnelOnStart(tunnel_t *t);

void udpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l);
void udpconnectorTunnelUpStreamEst(tunnel_t *t, line_t *l);
void udpconnectorTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void udpconnectorTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void udpconnectorTunnelUpStreamPause(tunnel_t *t, line_t *l);
void udpconnectorTunnelUpStreamResume(tunnel_t *t, line_t *l);

void udpconnectorTunnelDownStreamInit(tunnel_t *t, line_t *l);
void udpconnectorTunnelDownStreamEst(tunnel_t *t, line_t *l);
void udpconnectorTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void udpconnectorTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void udpconnectorTunnelDownStreamPause(tunnel_t *t, line_t *l);
void udpconnectorTunnelDownStreamResume(tunnel_t *t, line_t *l);

void udpconnectorLinestateInitialize(udpconnector_lstate_t *ls, tunnel_t *t, line_t *l, wio_t *io);
void udpconnectorLinestateDestroy(udpconnector_lstate_t *ls);
void udpconnectorOnRecvFrom(wio_t *io, sbuf_t *buf);
void udpconnectorOnClose(wio_t *io);
