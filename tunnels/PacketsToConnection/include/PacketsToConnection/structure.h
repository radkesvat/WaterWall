#pragma once

#include "wwapi.h"

#include "lwip/priv/tcp_priv.h"

typedef struct ptc_udp_flow_key_s
{
    uint32_t src_addr_network;
    uint32_t dest_addr_network;
    uint16_t src_port;
    uint16_t dest_port;
} ptc_udp_flow_key_t;

typedef struct ptc_fake_dns_name_key_s
{
    const char *name;
    uint8_t     len;
} ptc_fake_dns_name_key_t;

typedef struct ptc_fake_dns_entry_s ptc_fake_dns_entry_t;

typedef struct sbuf_ack_s
{
    sbuf_t  *buf;
    uint32_t written;
    uint32_t total;
} sbuf_ack_t;

static inline uint64_t ptcUdpFlowKeyHash(const ptc_udp_flow_key_t *key)
{
    uint64_t value = (((uint64_t) key->src_addr_network) << 32U) ^ key->dest_addr_network;
    value ^= ((uint64_t) key->src_port << 16U) ^ (uint64_t) key->dest_port;
    value ^= value >> 33U;
    value *= 0xff51afd7ed558ccduLL;
    value ^= value >> 33U;
    value *= 0xc4ceb9fe1a85ec53uLL;
    value ^= value >> 33U;
    return value;
}

#define i_type ptc_udp_flow_map_t // NOLINT
#define i_key  ptc_udp_flow_key_t // NOLINT
#define i_val  line_t *           // NOLINT
#define i_hash ptcUdpFlowKeyHash  // NOLINT
#define i_eq(x, y)                                                                                                     \
    ((x)->src_addr_network == (y)->src_addr_network && (x)->dest_addr_network == (y)->dest_addr_network &&             \
     (x)->src_port == (y)->src_port && (x)->dest_port == (y)->dest_port) // NOLINT
#include "stc/hmap.h"
#undef i_eq
#undef i_hash
#undef i_val
#undef i_key
#undef i_type

static inline uint64_t ptcFakeDnsNameKeyHash(const ptc_fake_dns_name_key_t *key)
{
    uint64_t hash = 1469598103934665603ULL;

    for (uint8_t i = 0; i < key->len; ++i)
    {
        hash ^= (uint8_t) key->name[i];
        hash *= 1099511628211ULL;
    }

    hash ^= key->len;
    hash *= 1099511628211ULL;
    return hash;
}

#define i_type     ptc_fake_dns_name_map_t                                                      // NOLINT
#define i_key      ptc_fake_dns_name_key_t                                                      // NOLINT
#define i_val      ptc_fake_dns_entry_t *                                                       // NOLINT
#define i_hash     ptcFakeDnsNameKeyHash                                                        // NOLINT
#define i_eq(x, y) ((x)->len == (y)->len && memoryCompare((x)->name, (y)->name, (x)->len) == 0) // NOLINT
#include "stc/hmap.h"
#undef i_eq
#undef i_hash
#undef i_val
#undef i_key
#undef i_type

#define i_type sbuf_ack_queue_t
#define i_key  sbuf_ack_t
#include "stc/deque.h"
#undef i_key
#undef i_type

enum
{
    kPtcDefaultUdpIdleTimeoutMs = 300U * 1000U
};

typedef struct interface_route_context_s interface_route_context_t;

typedef enum ptc_line_kind_e
{
    kPtcLineKindNone = 0,
    kPtcLineKindTcp,
    kPtcLineKindUdp
} ptc_line_kind_t;

struct interface_route_context_s
{
    interface_route_context_t *next;
    tunnel_t                  *tunnel;
    struct netif               netif;
    struct tcp_pcb            *tcp_pcb;
    struct udp_pcb            *udp_pcb;
    ptc_udp_flow_map_t         udp_flows;
    wid_t                      packet_wid;
};

struct ptc_fake_dns_entry_s
{
    ptc_fake_dns_entry_t *prev;
    ptc_fake_dns_entry_t *next;
    char                 *domain;
    uint32_t              fake_addr_network;
    uint32_t              index;
    uint8_t               domain_len;
};

typedef struct ptc_fake_dns_s
{
    ptc_fake_dns_name_map_t names;
    ptc_fake_dns_entry_t  **records;
    ptc_fake_dns_entry_t   *lru_head;
    ptc_fake_dns_entry_t   *lru_tail;
    ip4_addr_t              listen_addr;
    uint32_t                network_host;
    uint32_t                netmask_host;
    uint32_t                capacity;
    uint32_t                used;
    uint32_t                ttl;
    uint16_t                listen_port;
    bool                    enabled;
} ptc_fake_dns_t;

typedef struct ptc_tstate_s
{
    interface_route_context_t route_context4;
    interface_route_context_t route_context6;
    uint32_t                  udp_idle_timeout_ms;
    uint32_t                  ipv4_identification;
    ptc_fake_dns_t            fake_dns;
} ptc_tstate_t;

typedef struct ptc_lstate_s
{
    tunnel_t *tunnel;
    line_t   *line;

    union {
        struct tcp_pcb *tcp_pcb;
        struct udp_pcb *udp_pcb;
    };

    interface_route_context_t *route_ctx;
    buffer_queue_t             pause_queue;
    sbuf_ack_queue_t           ack_queue;

    uint64_t           udp_idle_deadline_ms;
    uint32_t           read_paused_len;
    ptc_udp_flow_key_t udp_flow_key;
    ip_addr_t          udp_local_addr;
    ip_addr_t          udp_peer_addr;
    uint16_t           udp_local_port;
    uint16_t           udp_peer_port;
    uint8_t            kind;
    bool               write_paused;
    bool               read_paused;
    bool               next_init_sent;
    bool               udp_idle_scheduled;
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
void ptcTunnelOnStop(tunnel_t *t);

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

void ptcLinestateInitialize(ptc_lstate_t *ls, tunnel_t *t, line_t *l, ptc_line_kind_t kind, void *pcb);
void ptcLinestateDestroy(ptc_lstate_t *ls);

err_t ptcNetifOutput(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr);

void  ptcDetachTcpPcbLocked(ptc_lstate_t *ls);
void  ptcDetachUdpFlowLocked(ptc_lstate_t *ls);
void  ptcCloseLineFromNetwork(tunnel_t *t, line_t *l);
void  ptcCloseLineFromDownstream(tunnel_t *t, line_t *l);
void  ptcArmUdpIdleOnOwnerThread(ptc_lstate_t *ls);
bool  ptcEnsureNextInit(tunnel_t *t, line_t *l, ptc_lstate_t *ls);
void  ptcOpenLineTask(tunnel_t *t, line_t *l);
void  ptcDeliverPayloadTask(tunnel_t *t, line_t *l, sbuf_t *buf);
void  ptcCloseLineTask(tunnel_t *t, line_t *l);
void  ptcResumeUpstreamTask(tunnel_t *t, line_t *l);
void  ptcUdpIdleTask(tunnel_t *t, line_t *l);
bool  ptcFakeDnsLoadSettings(ptc_tstate_t *ts, const cJSON *settings);
void  ptcFakeDnsDestroy(ptc_tstate_t *ts);
bool  ptcFakeDnsHandleIpv4UdpPacket(tunnel_t *t, line_t *packet_line, sbuf_t *buf, const struct ip_hdr *iphdr,
                                    const struct udp_hdr *udphdr);
bool  ptcFakeDnsApplyMappedDestination(tunnel_t *t, address_context_t *dest_ctx, const ip_addr_t *ip, uint16_t port,
                                       uint8_t protocol);
err_t ptcEnsureTcpListener(interface_route_context_t *route_ctx, tunnel_t *t, const ip_addr_t *dest_ip,
                           uint16_t dest_port);
err_t ptcEnsureUdpListener(interface_route_context_t *route_ctx, tunnel_t *t, const ip_addr_t *dest_ip,
                           uint16_t dest_port);
interface_route_context_t *ptcFindOrCreateRouteContextV4(tunnel_t *t, wid_t packet_wid, const ip4_addr_t *dest_ip);
void                       ptcDestroyRouteContexts(interface_route_context_t *root);

// Error callback: called when something goes wrong on the connection.
void lwipThreadPtcTcpConnectionErrorCallback(void *arg, err_t err);

// Accept callback: called when a new connection is accepted.
err_t lwipThreadPtcTcpAccptCallback(void *arg, struct tcp_pcb *newpcb, err_t err);
// Receive callback: called when new data is received.
err_t lwipThreadPtcTcpRecvCallback(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);

// UDP pretend accept callback: called with a newly-created per-flow PCB.
void ptcUdpAccept(void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);
// Receive callback: called when new data is received.
void ptcUdpReceived(void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);

void updateCheckSumTcp(u16_t *_hc, const void *_orig, const void *_new, int n);
void updateCheckSumUdp(u16_t *hc, const void *orig, const void *new, int n);

void  ptcFlushWriteQueue(ptc_lstate_t *lstate);
err_t ptcTcpSendCompleteCallback(void *arg, struct tcp_pcb *tpcb, u16_t len);
