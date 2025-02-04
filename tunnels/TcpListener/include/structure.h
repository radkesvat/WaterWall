#pragma once

#include "wwapi.h"

typedef struct tcplistener_tstate_s
{
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

} tcplistener_lstate_t;

enum
{
    kTunnelStateSize               = sizeof(tcplistener_tstate_t),
    kLineStateSize                 = sizeof(tcplistener_lstate_t),
    kDefaultKeepAliveTimeOutMs     = 60 * 1000, // same as NGINX
    kEstablishedKeepAliveTimeOutMs = 360 * 1000 // since the connection is established,
                                                // other end timetout is probably shorter
};

WW_EXPORT void         tcplistenerTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *tcplistenerTunnelCreate(node_t *node);
WW_EXPORT api_result_t tcplistenerTunnelApi(tunnel_t *instance, sbuf_t *message);

WW_EXPORT void tcplistenerTunnelOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
WW_EXPORT void tcplistenerTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
WW_EXPORT void tcplistenerTunnelOnPrepair(tunnel_t *t);
WW_EXPORT void tcplistenerTunnelOnStart(tunnel_t *t);

WW_EXPORT void tcplistenerTunnelUpStreamInit(tunnel_t *t, line_t *l);
WW_EXPORT void tcplistenerTunnelUpStreamEst(tunnel_t *t, line_t *l);
WW_EXPORT void tcplistenerTunnelUpStreamFinish(tunnel_t *t, line_t *l);
WW_EXPORT void tcplistenerTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
WW_EXPORT void tcplistenerTunnelUpStreamPause(tunnel_t *t, line_t *l);
WW_EXPORT void tcplistenerTunnelUpStreamResume(tunnel_t *t, line_t *l);

WW_EXPORT void tcplistenerTunnelDownStreamInit(tunnel_t *t, line_t *l);
WW_EXPORT void tcplistenerTunnelDownStreamEst(tunnel_t *t, line_t *l);
WW_EXPORT void tcplistenerTunnelDownStreamFinish(tunnel_t *t, line_t *l);
WW_EXPORT void tcplistenerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
WW_EXPORT void tcplistenerTunnelDownStreamPause(tunnel_t *t, line_t *l);
WW_EXPORT void tcplistenerTunnelDownStreamResume(tunnel_t *t, line_t *l);

void tcplistenerLinestateInitialize(tcplistener_lstate_t *ls, wid_t wid);
void tcplistenerLinestateDestroy(tcplistener_lstate_t *ls);

void tcplistenerFlushWriteQueue(tcplistener_lstate_t *lstate);
void tcplistenerOnInboundConnected(wevent_t *ev);
void tcplistenerOnWriteComplete(wio_t *io);
