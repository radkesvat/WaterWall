#pragma once

#include "wwapi.h"

typedef struct udplistener_tstate_s
{
    char    *listen_address;           // address to listen on
    char   **white_list_range;         // white list of client addresses (if any)
    char   **black_list_range;         // black list of client addresses (if any)
    int      listen_multiport_backend; // multiport backend (iptable? sockets?)
    uint16_t listen_port_min;          // min port to listen on (minimum of the range)
    uint16_t listen_port_max;          // max port to listen on (maximum of the range)

} udplistener_tstate_t;

typedef struct udplistener_lstate_s
{
    tunnel_t     *tunnel; // reference to the tunnel (UdpListener)
    line_t       *line;   // reference to the line
    udpsock_t    *uio;    // IO handle for the connection (socket)
    widle_item_t *idle_handle;

    // These fields are used internally for the queue implementation for TCP
    bool           read_paused : 1;

} udplistener_lstate_t;

enum
{
    kTunnelStateSize    = sizeof(udplistener_tstate_t),
    kLineStateSize      = sizeof(udplistener_lstate_t),
    kPauseQueueCapacity = 2,
    kUdpInitExpireTime  = 5 * 1000,
    kUdpKeepExpireTime  = 60 * 1000
};

WW_EXPORT void         udplistenerTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *udplistenerTunnelCreate(node_t *node);
WW_EXPORT api_result_t udplistenerTunnelApi(tunnel_t *instance, sbuf_t *message);

void udplistenerTunnelOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
void udplistenerTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void udplistenerTunnelOnPrepair(tunnel_t *t);
void udplistenerTunnelOnStart(tunnel_t *t);

void udplistenerTunnelUpStreamInit(tunnel_t *t, line_t *l);
void udplistenerTunnelUpStreamEst(tunnel_t *t, line_t *l);
void udplistenerTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void udplistenerTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void udplistenerTunnelUpStreamPause(tunnel_t *t, line_t *l);
void udplistenerTunnelUpStreamResume(tunnel_t *t, line_t *l);

void udplistenerTunnelDownStreamInit(tunnel_t *t, line_t *l);
void udplistenerTunnelDownStreamEst(tunnel_t *t, line_t *l);
void udplistenerTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void udplistenerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void udplistenerTunnelDownStreamPause(tunnel_t *t, line_t *l);
void udplistenerTunnelDownStreamResume(tunnel_t *t, line_t *l);

void udplistenerLinestateInitialize(udplistener_lstate_t *ls, line_t *l, tunnel_t *t, udpsock_t *uio,
                                    uint16_t real_localport);
void udplistenerLinestateDestroy(udplistener_lstate_t *ls);

void onUdpListenerFilteredPayloadReceived(wevent_t *ev);

