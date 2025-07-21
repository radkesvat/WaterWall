#pragma once

#include "wwapi.h"

typedef struct udpstatelesssocket_tstate_s
{
    TunnelFlowRoutinePayload WriteReceivedPacket; // function to give received data to the next/prev tunnel
    tunnel_t* write_tunnel; // tunnel to write data to

    // These fields are read from json
    char    *listen_address; // address to listen on (ip)
    uint16_t listen_port;    // port to listen on
    int      fwmark;         // fwmark to set on the socket

    wio_t *io;     // socket file descriptor
    wid_t  io_wid; // the worker id that created the io

} udpstatelesssocket_tstate_t;

typedef struct udpstatelesssocket_lstate_s
{
    int unused;
} udpstatelesssocket_lstate_t;

enum
{
    kTunnelStateSize = sizeof(udpstatelesssocket_tstate_t),
    kLineStateSize   = sizeof(udpstatelesssocket_lstate_t)
};

WW_EXPORT void         udpstatelesssocketTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *udpstatelesssocketTunnelCreate(node_t *node);
WW_EXPORT api_result_t udpstatelesssocketTunnelApi(tunnel_t *instance, sbuf_t *message);

void udpstatelesssocketTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void udpstatelesssocketTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void udpstatelesssocketTunnelOnPrepair(tunnel_t *t);
void udpstatelesssocketTunnelOnStart(tunnel_t *t);

void udpstatelesssocketTunnelUpStreamInit(tunnel_t *t, line_t *l);
void udpstatelesssocketTunnelUpStreamEst(tunnel_t *t, line_t *l);
void udpstatelesssocketTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void udpstatelesssocketTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void udpstatelesssocketTunnelUpStreamPause(tunnel_t *t, line_t *l);
void udpstatelesssocketTunnelUpStreamResume(tunnel_t *t, line_t *l);

void udpstatelesssocketTunnelDownStreamInit(tunnel_t *t, line_t *l);
void udpstatelesssocketTunnelDownStreamEst(tunnel_t *t, line_t *l);
void udpstatelesssocketTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void udpstatelesssocketTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void udpstatelesssocketTunnelDownStreamPause(tunnel_t *t, line_t *l);
void udpstatelesssocketTunnelDownStreamResume(tunnel_t *t, line_t *l);

void udpstatelesssocketLinestateInitialize(udpstatelesssocket_lstate_t *ls);
void udpstatelesssocketLinestateDestroy(udpstatelesssocket_lstate_t *ls);

void udpstatelesssocketOnRecvFrom(wio_t *io, sbuf_t *buf);
void UdpStatelessLocalThreadSocketUpStream(struct worker_s *worker, void *arg1, void *arg2, void *arg3);
