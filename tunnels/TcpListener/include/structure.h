#pragma once

#include "wwapi.h"

typedef struct tcplistener_tstate_s
{
    widle_table_t *idle_table; // idle table for closing dead connections

    // These fields are read from json
    char    *listen_address;           // address to listen on
    char   **white_list_range;         // white list of client addresses (if any)
    char   **black_list_range;         // black list of client addresses (if any)
    int      listen_multiport_backend; // multiport backend (iptable? sockets?)
    uint16_t listen_port_min;          // min port to listen on (minimum of the range)
    uint16_t listen_port_max;          // max port to listen on (maximum of the range)
    bool     option_tcp_no_delay;      // apply TCP no delay option on sockets

} tcplistener_tstate_t;

typedef struct tcplistener_lstate_s
{
    tunnel_t     *tunnel;      // reference to the tunnel (TcpListener)
    line_t       *line;        // reference to the line
    wio_t        *io;          // IO handle for the connection (socket)
    widle_item_t *idle_handle; // reference to the idle item for this connection

    // These fields are used internally for the queue implementation for TCP
    buffer_queue_t pause_queue;
    bool           write_paused : 1;
    bool           read_paused : 1;

} tcplistener_lstate_t;

enum
{
    kTunnelStateSize               = sizeof(tcplistener_tstate_t),
    kLineStateSize                 = sizeof(tcplistener_lstate_t),
    kMaxPauseQueueSize             = 1024 * 1024, // 1MB
    kDefaultKeepAliveTimeOutMs     = 5 * 1000,    // same as NGINX
    kEstablishedKeepAliveTimeOutMs = 300 * 1000,  // since the connection is established,

    kPauseQueueCapacity = 2
};

WW_EXPORT void         tcplistenerTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *tcplistenerTunnelCreate(node_t *node);
WW_EXPORT api_result_t tcplistenerTunnelApi(tunnel_t *instance, sbuf_t *message);

void tcplistenerTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void tcplistenerTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void tcplistenerTunnelOnPrepair(tunnel_t *t);
void tcplistenerTunnelOnStart(tunnel_t *t);

void tcplistenerTunnelUpStreamInit(tunnel_t *t, line_t *l);
void tcplistenerTunnelUpStreamEst(tunnel_t *t, line_t *l);
void tcplistenerTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void tcplistenerTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tcplistenerTunnelUpStreamPause(tunnel_t *t, line_t *l);
void tcplistenerTunnelUpStreamResume(tunnel_t *t, line_t *l);

void tcplistenerTunnelDownStreamInit(tunnel_t *t, line_t *l);
void tcplistenerTunnelDownStreamEst(tunnel_t *t, line_t *l);
void tcplistenerTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void tcplistenerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tcplistenerTunnelDownStreamPause(tunnel_t *t, line_t *l);
void tcplistenerTunnelDownStreamResume(tunnel_t *t, line_t *l);

void tcplistenerLinestateInitialize(tcplistener_lstate_t *ls, wio_t *io, tunnel_t *t, line_t *l);
void tcplistenerLinestateDestroy(tcplistener_lstate_t *ls);

void tcplistenerFlushWriteQueue(tcplistener_lstate_t *lstate);
void tcplistenerOnInboundConnected(wevent_t *ev);
void tcplistenerOnWriteComplete(wio_t *io);

void tcplistenerOnIdleConnectionExpire(widle_item_t *idle_tcp);
