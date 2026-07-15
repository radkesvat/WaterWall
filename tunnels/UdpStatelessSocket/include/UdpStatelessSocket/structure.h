#pragma once

#include "wwapi.h"

enum
{
    kUdpStatelessSocketDnsRefreshIntervalMs = 30 * 60 * 1000,
    kUdpStatelessSocketInitExpireTime       = 30 * 1000,
    kUdpStatelessSocketKeepExpireTime       = 300 * 1000
};

typedef struct udpstatelesssocket_dns_cache_entry_s udpstatelesssocket_dns_cache_entry_t;
typedef struct udpstatelesssocket_send_request_s    udpstatelesssocket_send_request_t;

struct udpstatelesssocket_dns_cache_entry_s
{
    char                                 *domain;
    uint16_t                              port;
    int                                   strategy;
    sockaddr_u                            peer_addr;
    unsigned int                          resolved_at_ms;
    udpstatelesssocket_dns_cache_entry_t *next;
};

struct udpstatelesssocket_send_request_s
{
    threadsafe_generic_pool_t *pool;
    tunnel_t                  *tunnel;
    sbuf_t                    *buf;
    sockaddr_u                 peer_addr;
};

typedef struct udpstatelesssocket_tstate_s
{
    udpsock_t socket; // UDP socket side-data, including worker-local peer idle tables
    master_pool_t             *send_request_master_pool;
    threadsafe_generic_pool_t **send_request_pools;

    // These fields are read from json
    char    *listen_address; // address to listen on (ip)
    char    *interface_name; // optional network device for the UDP socket
    uint16_t listen_port;    // port to listen on
    int      fwmark;         // fwmark to set on the socket
    int      send_buffer_size;
    int      recv_buffer_size;
    bool     verbose;

    wid_t io_wid; // the worker id that created the io
    bool  is_chain_end;

    bool source_ip_configured;

    wmutex_t                              dns_cache_mutex;
    udpstatelesssocket_dns_cache_entry_t *dns_cache;
} udpstatelesssocket_tstate_t;

typedef struct udpstatelesssocket_lstate_s
{
    tunnel_t          *tunnel;
    line_t            *line;
    local_idle_item_t *idle_handle;
    sockaddr_u         peer_addr;
    sockaddr_u         local_addr;
    bool               read_paused : 1;
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
void udpstatelesssocketTunnelOnStop(tunnel_t *t);
void udpstatelesssocketTunnelOnWorkerStop(tunnel_t *t, wid_t wid);

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

void udpstatelesssocketLinestateInitialize(udpstatelesssocket_lstate_t *ls, line_t *l, tunnel_t *t,
                                           local_idle_item_t *idle_handle, const sockaddr_u *peer_addr,
                                           const sockaddr_u *local_addr);
void udpstatelesssocketLinestateDestroy(udpstatelesssocket_lstate_t *ls);

bool                udpstatelesssocketLinestateOwnsLine(tunnel_t *t, line_t *l, udpstatelesssocket_lstate_t *ls);
local_idle_table_t *udpstatelesssocketGetWorkerIdleTable(udpstatelesssocket_tstate_t *ts);
local_idle_table_t *udpstatelesssocketGetLineIdleTable(udpstatelesssocket_tstate_t *ts, line_t *l);
void                udpstatelesssocketCloseOwnedLineFromAdjacent(tunnel_t *t, line_t *l, bool is_chain_end);
void udpstatelesssocketOnRecvFrom(wio_t *io, sbuf_t *buf);
void udpstatelesssocketTunnelWritePayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void udpstatelesssocketLocalThreadSocketUpStream(void *worker, void *arg1, void *arg2, void *arg3);
