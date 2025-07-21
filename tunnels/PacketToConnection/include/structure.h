#pragma once

#include "wwapi.h"

#include "lwip/priv/tcp_priv.h"

enum
{
    kTcpWriteRetryTime = 75
};

#define SHOW_ALL_LOGS 0

#define i_type vec_ports_t // NOLINT
#define i_key  uint16_t    // NOLINT
#define i_use_cmp
#include "stc/vec.h"

typedef struct sbuf_ack_s
{
    sbuf_t  *buf;
    uint32_t written;
    uint32_t total;
} sbuf_ack_t;

#define i_type sbuf_ack_queue_t
#define i_key  sbuf_ack_t
#include "stc/deque.h"

typedef struct interface_route_context_s
{
    struct interface_route_context_s *next;
    struct netif                      netif;
    uint32_t                          last_tick;
    bool                              tcp_map_overflow;
    bool                              udp_map_overflow;
    vec_ports_t                       tcp_ports;
    vec_ports_t                       udp_ports;

} interface_route_context_t;

typedef struct ptc_tstate_s
{
    /* Main network interface */
    // struct netif netif;

    interface_route_context_t route_context4;
    interface_route_context_t route_context6;

} ptc_tstate_t;

typedef struct ptc_lstate_s
{

    tunnel_t *tunnel; // reference to the tunnel (TcpListener)
    line_t   *line;   // reference to the line

    // this belongs to tcpip stack, hold the tcpip mutex before accessing this
    union {
        struct tcp_pcb *tcp_pcb;
        struct udp_pcb *udp_pcb;
    };

    wtimer_t *timer; // this is used when tcpip stack cannot accept the data, we should query it again

    // These fields are used internally for the queue implementation for TCP
    buffer_queue_t   pause_queue;
    sbuf_ack_queue_t ack_queue;

    atomic_ulong messages;

    uint32_t read_paused_len;

    bool is_tcp : 1;
    bool write_paused : 1;
    bool read_paused : 1;
    bool established : 1; // this flag is set when the connection is established (est recevied from upstream)
    bool init_sent : 1;

} ptc_lstate_t;

typedef struct my_custom_pbuf
{
    struct pbuf_custom p;
    sbuf_t            *sbuf;
} my_custom_pbuf_t;

LWIP_MEMPOOL_PROTOTYPE(RX_POOL);
enum
{
    kTunnelStateSize = sizeof(ptc_tstate_t),
    kLineStateSize   = sizeof(ptc_lstate_t)
};

WW_EXPORT void         ptcTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *ptcTunnelCreate(node_t *node);
WW_EXPORT api_result_t ptcTunnelApi(tunnel_t *instance, sbuf_t *message);

void ptcTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void ptcTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void ptcTunnelOnPrepair(tunnel_t *t);
void ptcTunnelOnStart(tunnel_t *t);

void ptcTunnelUpStreamInit(tunnel_t *t, line_t *l);
void ptcTunnelUpStreamEst(tunnel_t *t, line_t *l);
void ptcTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void ptcTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void ptcTunnelUpStreamPause(tunnel_t *t, line_t *l);
void ptcTunnelUpStreamResume(tunnel_t *t, line_t *l);

void ptcTunnelDownStreamInit(tunnel_t *t, line_t *l);
void ptcTunnelDownStreamEst(tunnel_t *t, line_t *l);
void ptcTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void ptcTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void ptcTunnelDownStreamPause(tunnel_t *t, line_t *l);
void ptcTunnelDownStreamResume(tunnel_t *t, line_t *l);

void ptcLinestateInitialize(ptc_lstate_t *ls, wid_t wid, tunnel_t *t, line_t *l, void *pcb);
void ptcLinestateDestroy(ptc_lstate_t *ls);

err_t ptcHookV4(struct pbuf *p, struct netif *inp);
err_t ptcNetifOutput(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr);
err_t ptcHandleTcpInput(struct pbuf *p, struct netif *inp);

// Error callback: called when something goes wrong on the connection.
void lwipThreadPtcTcpConnectionErrorCallback(void *arg, err_t err);

// Accept callback: called when a new connection is accepted.
err_t lwipThreadPtcTcpAccptCallback(void *arg, struct tcp_pcb *newpcb, err_t err);
// Receive callback: called when new data is received.
err_t lwipThreadPtcTcpRecvCallback(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);

// Receive callback: called when new data is received.
void ptcUdpReceived(void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);

void updateCheckSumTcp(u16_t *_hc, const void *_orig, const void *_new, int n);
void updateCheckSumUdp(u16_t *hc, const void *orig, const void *new, int n);

void  ptcFlushWriteQueue(ptc_lstate_t *lstate);
err_t ptcTcpSendCompleteCallback(void *arg, struct tcp_pcb *tpcb, u16_t len);
