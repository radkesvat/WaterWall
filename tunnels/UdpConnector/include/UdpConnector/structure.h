#pragma once

#include "DomainResolver/interface.h"
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

typedef struct udpconnector_domain_resolver_lstate_s
{
    address_context_t packet_base_dest_ctx;
    uint32_t          packet_initial_destination_index;
    bool              route_destination_pinned;
} udpconnector_domain_resolver_lstate_t;

typedef struct udpconnector_packet_dns_request_s udpconnector_packet_dns_request_t;
typedef struct udpconnector_packet_destination_s udpconnector_packet_destination_t;

typedef struct udpconnector_peer_key_s
{
    uint16_t family; // AF_INET or AF_INET6
    uint16_t port;   // port in network byte order
    union {
        uint32_t ipv4;     // network byte order
        uint8_t  ipv6[16]; // 16 bytes
    } addr;
    uint32_t scope_id; // sin6_scope_id
} udpconnector_peer_key_t;

#if defined(UDPCONNECTOR_POOL_TEST_HOOKS)
extern bool g_udpconnector_pool_test_force_hash_zero;
extern bool g_udpconnector_pool_test_fail_socket_alloc;
extern bool g_udpconnector_pool_test_fail_binding_alloc;
extern bool g_udpconnector_pool_test_fail_socket_map_insert;
extern bool g_udpconnector_pool_test_fail_line_map_insert;
#endif

static inline udpconnector_peer_key_t udpconnectorPeerKeyFromSockAddr(const sockaddr_u *sa)
{
    udpconnector_peer_key_t key;
    memoryZero(&key, sizeof(key));
    key.family = sa->sa.sa_family;
    if (sa->sa.sa_family == AF_INET)
    {
        key.port      = sa->sin.sin_port;
        key.addr.ipv4 = sa->sin.sin_addr.s_addr;
        key.scope_id  = 0;
    }
    else if (sa->sa.sa_family == AF_INET6)
    {
        key.port = sa->sin6.sin6_port;
        memoryCopy(key.addr.ipv6, sa->sin6.sin6_addr.s6_addr, sizeof(key.addr.ipv6));
        key.scope_id = sa->sin6.sin6_scope_id;
    }
    return key;
}

static inline bool udpconnectorPeerKeyEquals(const udpconnector_peer_key_t *a, const udpconnector_peer_key_t *b)
{
    if (a->family != b->family || a->port != b->port)
    {
        return false;
    }
    if (a->family == AF_INET)
    {
        return a->addr.ipv4 == b->addr.ipv4;
    }
    if (a->family == AF_INET6)
    {
        return a->scope_id == b->scope_id && memoryCompare(a->addr.ipv6, b->addr.ipv6, sizeof(a->addr.ipv6)) == 0;
    }
    return false;
}

static inline size_t udpconnectorPeerKeyHash(const udpconnector_peer_key_t *key)
{
#if defined(UDPCONNECTOR_POOL_TEST_HOOKS)
    if (g_udpconnector_pool_test_force_hash_zero)
    {
        return 0;
    }
#endif
    uint64_t h = ((uint64_t) key->family << 16U) ^ (uint64_t) key->port;
    if (key->family == AF_INET)
    {
        h ^= ((uint64_t) key->addr.ipv4) << 32U;
    }
    else if (key->family == AF_INET6)
    {
        uint64_t w0, w1;
        memoryCopy(&w0, &key->addr.ipv6[0], 8);
        memoryCopy(&w1, &key->addr.ipv6[8], 8);
        h ^= w0 ^ (w1 << 1U) ^ (((uint64_t) key->scope_id) << 32U);
    }
    h ^= h >> 33U;
    h *= 0xff51afd7ed558ccduLL;
    h ^= h >> 33U;
    h *= 0xc4ceb9fe1a85ec53uLL;
    h ^= h >> 33U;
    return (size_t) h;
}

typedef struct udpconnector_binding_s udpconnector_binding_t;

#define i_type udpconnector_peer_binding_map // NOLINT
#define i_key  udpconnector_peer_key_t       // NOLINT
#define i_val  udpconnector_binding_t *      // NOLINT
#define i_hash udpconnectorPeerKeyHash       // NOLINT
#define i_eq   udpconnectorPeerKeyEquals     // NOLINT
#include "stc/hmap.h"
#undef i_eq
#undef i_hash
#undef i_val
#undef i_key
#undef i_type

typedef udpconnector_peer_binding_map udpconnector_peer_binding_map_t;

typedef enum udpconnector_pool_socket_state_e
{
    kUdpConnectorPoolSocketAccepting = 0,
    kUdpConnectorPoolSocketDraining,
    kUdpConnectorPoolSocketClosing
} udpconnector_pool_socket_state_e;

typedef struct udpconnector_worker_pool_s udpconnector_worker_pool_t;
typedef struct udpconnector_pool_socket_s udpconnector_pool_socket_t;
typedef struct udpconnector_lstate_s      udpconnector_lstate_t;

struct udpconnector_pool_socket_s
{
    tunnel_t                        *tunnel;
    udpconnector_worker_pool_t      *worker_pool;
    wid_t                            wid;
    int                              family;
    udpconnector_pool_socket_state_e state;
    wio_t                           *io;
    udpconnector_peer_binding_map_t  peer_map;
    uint32_t                         active_bindings_count;
    bool                             linked;

    udpconnector_pool_socket_t *prev;
    udpconnector_pool_socket_t *next;
};

struct udpconnector_binding_s
{
    udpconnector_pool_socket_t *socket;
    udpconnector_peer_key_t     peer_key;
    sockaddr_u                  peer_addr;
    line_t                     *line;
    udpconnector_lstate_t      *ls;
    bool                        active;
    bool                        socket_linked;
    bool                        line_linked;

    udpconnector_binding_t *line_prev;
    udpconnector_binding_t *line_next;
};

struct udpconnector_worker_pool_s
{
    wid_t                       wid;
    bool                        quiescing;
    uint64_t                    next_line_idle_id;
    local_idle_table_t         *idle_table;
    udpconnector_pool_socket_t *v4_sockets;
    udpconnector_pool_socket_t *v6_sockets;
    uint32_t                    v4_sockets_count;
    uint32_t                    v6_sockets_count;
    uint64_t                    active_bindings_count;
};

typedef enum udpconnector_detach_disposition_e
{
    kUdpConnectorDetachFinish = 0,
    kUdpConnectorDetachIdleExpire,
    kUdpConnectorDetachSocketFailure,
    kUdpConnectorDetachQueueOverflow,
    kUdpConnectorDetachInitRollback,
    kUdpConnectorDetachWorkerDrain
} udpconnector_detach_disposition_t;

typedef struct udpconnector_tstate_s
{
    udpconnector_worker_pool_t *worker_pools; // worker-local pools for pooling UDP sockets

    node_t        domain_resolver_node;
    tunnel_t     *domain_resolver_tunnel;
    struct cJSON *domain_resolver_settings;

    dynamic_value_t   dest_addr_selected; // selected destination address
    dynamic_value_t   dest_port_selected; // selected destination port
    address_context_t constant_dest_addr; // constant destination address for the connection
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

struct udpconnector_lstate_s
{
    tunnel_t                          *tunnel;      // reference to the tunnel
    line_t                            *line;        // reference to the line
    local_idle_item_t                 *idle_handle; // reference to the idle item for this line
    uint64_t                           line_idle_id;
    udpconnector_binding_t            *fixed_binding; // single binding for connection/pinned mode
    udpconnector_peer_binding_map_t    peer_bindings; // map for packet mode
    udpconnector_binding_t            *bindings_head; // doubly linked list of all bindings on this line
    uint32_t                           bindings_count;
    udpconnector_binding_t            *last_send_binding; // non-owning pointer to last send binding
    udpconnector_packet_dns_request_t *packet_dns_requests;
    udpconnector_packet_destination_t *packet_destinations;
    uint32_t                           packet_destinations_count;
    uint32_t                           packet_initial_destination_index;
    address_context_t                  packet_base_dest_ctx;
    sockaddr_u                         peer_addr; // initial/selected remote peer for this line
    buffer_queue_t                     pause_queue;
    bool                               read_paused : 1;      // whether the read is paused
    bool                               established : 1;      // whether downstream est was sent
    bool                               write_paused : 1;     // whether upstream writes are queued
    bool                               queue_pause_sent : 1; // whether downstream pause was sent for the queue
    bool                               route_destination_pinned : 1;
};

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

WW_EXPORT void         udpconnectorTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *udpconnectorTunnelCreate(node_t *node);
WW_EXPORT api_result_t udpconnectorTunnelApi(tunnel_t *instance, sbuf_t *message);

void udpconnectorTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void udpconnectorTunnelOnPrepair(tunnel_t *t);
void udpconnectorTunnelOnStart(tunnel_t *t);
void udpconnectorTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context);
void udpconnectorTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);

void udpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l);
void udpconnectorTunnelUpStreamEst(tunnel_t *t, line_t *l);
void udpconnectorTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void udpconnectorTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void udpconnectorTunnelUpStreamPause(tunnel_t *t, line_t *l);
void udpconnectorTunnelUpStreamResume(tunnel_t *t, line_t *l);

bool udpconnectorDomainResolverPrepare(tunnel_t *resolver, tunnel_t *connector, line_t *l,
                                       domainresolver_direction_t direction, void *user_lstate);
void udpconnectorDomainResolverUserStateDestroy(tunnel_t *resolver, tunnel_t *connector, line_t *l, void *user_lstate);

bool   udpconnectorLinestateInitialize(udpconnector_lstate_t *ls, tunnel_t *t, line_t *l);
void   udpconnectorLinestateDestroy(udpconnector_lstate_t *ls);
void   udpconnectorCancelPacketDnsRequests(udpconnector_lstate_t *ls);
size_t udpconnectorQueuedWriteBytes(udpconnector_lstate_t *ls);
void   udpconnectorFlushWriteQueue(udpconnector_lstate_t *ls);
bool   udpconnectorReplayWriteQueue(udpconnector_lstate_t *ls);

local_idle_table_t         *udpconnectorGetWorkerIdleTable(udpconnector_tstate_t *ts);
local_idle_table_t         *udpconnectorGetLineIdleTable(udpconnector_tstate_t *ts, line_t *l);
udpconnector_worker_pool_t *udpconnectorGetLineWorkerPool(udpconnector_tstate_t *ts, line_t *l);

udpconnector_pool_socket_t *udpconnectorPoolSocketCreate(tunnel_t *t, udpconnector_worker_pool_t *pool, int family);
void                        udpconnectorPoolSocketRetire(udpconnector_pool_socket_t *sock);

udpconnector_binding_t *udpconnectorAcquireBinding(tunnel_t *t, line_t *l, udpconnector_lstate_t *ls,
                                                   const sockaddr_u *peer_addr);
void udpconnectorBindingDetach(udpconnector_binding_t *binding, udpconnector_detach_disposition_t disposition);
void udpconnectorLineDetach(tunnel_t *t, line_t *l, udpconnector_lstate_t *ls,
                            udpconnector_detach_disposition_t disposition);

void udpconnectorOnSocketRecvFrom(wio_t *io, sbuf_t *buf);
void udpconnectorOnSocketClose(wio_t *io);

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
void udpconnectorTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);

#if defined(UDPCONNECTOR_POOL_TEST_HOOKS)
uint32_t                         udpconnectorTestGetSocketCount(tunnel_t *t, wid_t wid, int family);
uint32_t                         udpconnectorTestGetSocketBindingCount(const udpconnector_pool_socket_t *sock);
udpconnector_pool_socket_state_e udpconnectorTestGetSocketState(const udpconnector_pool_socket_t *sock);
wio_t                           *udpconnectorTestGetSocketWio(const udpconnector_pool_socket_t *sock);
udpconnector_pool_socket_t      *udpconnectorTestGetFirstSocket(tunnel_t *t, wid_t wid, int family);
udpconnector_binding_t          *udpconnectorTestGetLineFixedBinding(const udpconnector_lstate_t *ls);
uint32_t                         udpconnectorTestGetLineBindingCount(const udpconnector_lstate_t *ls);
udpconnector_binding_t          *udpconnectorTestGetLineFirstBinding(const udpconnector_lstate_t *ls);
bool udpconnectorTestFlushPacketDestinationQueue(tunnel_t *t, line_t *l, uint32_t destination_index);
#endif
