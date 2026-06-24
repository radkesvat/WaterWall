#pragma once

#include "wwapi.h"

enum udp_connector_dynamic_value_status
{

    kDvsFromSource = kDvsFirstOption,
    kDvsFromDest,
    kDvsRandom // currently only meaningful for port selection
};

typedef enum udpconnector_balance_mode_e
{
    kUdpConnectorBalanceModeConnection = 0,
    kUdpConnectorBalanceModePacket
} udpconnector_balance_mode_e;

typedef struct udpconnector_domain_setup_tstate_s
{
    tunnel_t *connector_tunnel;
} udpconnector_domain_setup_tstate_t;

typedef struct udpconnector_domain_setup_lstate_s
{
    address_context_t packet_base_dest_ctx;
    uint32_t          packet_initial_destination_index;
} udpconnector_domain_setup_lstate_t;

typedef struct udpconnector_packet_dns_request_s udpconnector_packet_dns_request_t;
typedef struct udpconnector_packet_destination_s udpconnector_packet_destination_t;

typedef struct udpconnector_tstate_s
{
    local_idle_table_t **idle_tables; // worker-local idle tables for closing dead connections

    node_t        domain_setup_node;
    tunnel_t     *domain_setup_tunnel;
    node_t        domain_resolver_node;
    tunnel_t     *domain_resolver_tunnel;
    struct cJSON *domain_resolver_settings;

    dynamic_value_t   dest_addr_selected; // selected destination address
    dynamic_value_t   dest_port_selected; // selected destination port
    address_context_t constant_dest_addr; // constant destination address for the connection
    bool              reuse_addr;         // whether to reuse address
    int               domain_strategy;    // DNS resolution strategy
    int               fwmark;             // firewall mark on linux (beta)
    int               send_buffer_size;   // optional socket SO_SNDBUF size
    int               recv_buffer_size;   // optional socket SO_RCVBUF size
    char             *interface_name;     // optional network device for outbound sockets
    char             *source_ip;          // optional local source IP for outbound sockets

    udpconnector_balance_mode_e balance_mode;

    uint16_t random_dest_port_x; // lower bound of random port range (used when dest_port_selected.status == kDvsRandom)
    uint16_t random_dest_port_y; // upper bound of random port range (used when dest_port_selected.status == kDvsRandom)

    struct udpconnector_destination_s *destinations;
    uint32_t                           destinations_count;
    uint64_t                           destinations_weight_total;
} udpconnector_tstate_t;

typedef struct udpconnector_destination_s
{
    dynamic_value_t   dest_addr_selected;
    dynamic_value_t   dest_port_selected;
    address_context_t constant_dest_addr;
    uint16_t          random_dest_port_x;
    uint16_t          random_dest_port_y;
    uint32_t          weight;
} udpconnector_destination_t;

struct udpconnector_packet_dns_request_s
{
    tunnel_t *tunnel;
    line_t   *line;
    char     *domain;
    uint32_t  destination_index;
    int       strategy;
    bool      cancelled;

    udpconnector_packet_dns_request_t *prev;
    udpconnector_packet_dns_request_t *next;
};

struct udpconnector_packet_destination_s
{
    address_context_t dest_ctx;
    buffer_queue_t    pending_queue;
    bool              has_context : 1;
    bool              resolving : 1;
};

typedef struct udpconnector_lstate_s
{
    tunnel_t                          *tunnel;      // reference to the tunnel
    line_t                            *line;        // reference to the line
    wio_t                             *io;          // IO handle for the connection (socket)
    local_idle_item_t                 *idle_handle; // reference to the idle item for this connection
    udpconnector_packet_dns_request_t *packet_dns_requests;
    udpconnector_packet_destination_t *packet_destinations;
    uint32_t                           packet_destinations_count;
    uint32_t                           packet_initial_destination_index;
    address_context_t                  packet_base_dest_ctx;
    sockaddr_u                         peer_addr; // selected remote peer for this line
    buffer_queue_t                     pause_queue;
    bool                               read_paused : 1;      // whether the read is paused
    bool                               established : 1;      // whether downstream est was sent
    bool                               write_paused : 1;     // whether upstream writes are queued
    bool                               queue_pause_sent : 1; // whether downstream pause was sent for the queue

} udpconnector_lstate_t;

enum
{
    kTunnelStateSize       = sizeof(udpconnector_tstate_t),
    kLineStateSize         = sizeof(udpconnector_lstate_t),
    kUdpInitExpireTime     = 30 * 1000,
    kUdpKeepExpireTime     = 300 * 1000,
    kUdpMaxPauseQueueSize  = (1U << 24), // 16MB
    kUdpMinPauseQueueSize  = (1U << 10), // 1KB
    kUdpPauseQueueCapacity = 2
};

static inline hash_t udpconnectorIdleKey(const wio_t *io)
{
    return (hash_t) wioGetID((wio_t *) io);
}

static inline void udpconnectorDestinationDeinit(udpconnector_destination_t *destination)
{
    dynamicvalueDestroy(destination->dest_addr_selected);
    dynamicvalueDestroy(destination->dest_port_selected);
}

static inline bool udpconnectorDynamicValueUsesLineContext(const dynamic_value_t *value)
{
    return value->status == kDvsFromSource || value->status == kDvsFromDest;
}

static inline bool udpconnectorDestinationUsesLineContext(const dynamic_value_t *dest_addr_selected,
                                                          const dynamic_value_t *dest_port_selected)
{
    return udpconnectorDynamicValueUsesLineContext(dest_addr_selected) ||
           udpconnectorDynamicValueUsesLineContext(dest_port_selected);
}

WW_EXPORT void         udpconnectorTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *udpconnectorTunnelCreate(node_t *node);
WW_EXPORT api_result_t udpconnectorTunnelApi(tunnel_t *instance, sbuf_t *message);

void udpconnectorTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void udpconnectorTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void udpconnectorTunnelOnPrepair(tunnel_t *t);
void udpconnectorTunnelOnStart(tunnel_t *t);
void udpconnectorTunnelOnStop(tunnel_t *t);
void udpconnectorTunnelOnWorkerStop(tunnel_t *t, wid_t wid);

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
void udpconnectorDomainSetupTunnelUpStreamInit(tunnel_t *t, line_t *l);
void udpconnectorDomainSetupTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void udpconnectorDomainSetupTunnelDownStreamFinish(tunnel_t *t, line_t *l);

void   udpconnectorLinestateInitialize(udpconnector_lstate_t *ls, tunnel_t *t, line_t *l, wio_t *io);
void   udpconnectorLinestateDestroy(udpconnector_lstate_t *ls);
void   udpconnectorDomainSetupLinestateInitialize(udpconnector_domain_setup_lstate_t *ls);
void   udpconnectorDomainSetupLinestateDestroy(udpconnector_domain_setup_lstate_t *ls);
void   udpconnectorCancelPacketDnsRequests(udpconnector_lstate_t *ls);
void   udpconnectorOnRecvFrom(wio_t *io, sbuf_t *buf);
void   udpconnectorOnClose(wio_t *io);
size_t udpconnectorQueuedWriteBytes(udpconnector_lstate_t *ls);
void   udpconnectorFlushWriteQueue(udpconnector_lstate_t *ls);
bool   udpconnectorReplayWriteQueue(udpconnector_lstate_t *ls);

local_idle_table_t *udpconnectorGetWorkerIdleTable(udpconnector_tstate_t *ts);
local_idle_table_t *udpconnectorGetLineIdleTable(udpconnector_tstate_t *ts, line_t *l);

void udpconnectorOnIdleConnectionExpire(local_idle_item_t *idle_udp);

uint32_t                          udpconnectorSelectWeightedDestinationIndex(const udpconnector_tstate_t *ts);
const udpconnector_destination_t *udpconnectorSelectWeightedDestination(const udpconnector_tstate_t *ts);
void                              udpconnectorSetupDestinationAddress(const dynamic_value_t   *dest_addr_selected,
                                                                      const address_context_t *constant_dest_addr, address_context_t *dest_ctx,
                                                                      const address_context_t *original_dest_ctx, address_context_t *src_ctx);
void                              udpconnectorSetupDestinationPort(const dynamic_value_t   *dest_port_selected,
                                                                   const address_context_t *constant_dest_addr, uint16_t random_dest_port_x,
                                                                   uint16_t random_dest_port_y, address_context_t *dest_ctx,
                                                                   const address_context_t *original_dest_ctx, address_context_t *src_ctx);
const dns_resolved_addr_t        *udpconnectorSelectResolvedAddress(const dns_resolved_addr_t *addrs, size_t naddrs,
                                                                    int strategy);
bool udpconnectorApplyResolvedAddress(address_context_t *dest_ctx, const dns_resolved_addr_t *resolved);
