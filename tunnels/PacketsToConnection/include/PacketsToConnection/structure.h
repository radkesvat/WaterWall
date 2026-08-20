#pragma once

#include "wwapi.h"

#include "devices/device_frag_settlement.h"
#include "quiescence_gate.h"

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

static inline size_t ptcUdpFlowKeyHash(const ptc_udp_flow_key_t *key)
{
    uint64_t value = (((uint64_t) key->src_addr_network) << 32U) ^ key->dest_addr_network;
    value ^= ((uint64_t) key->src_port << 16U) ^ (uint64_t) key->dest_port;
    value ^= value >> 33U;
    value *= 0xff51afd7ed558ccduLL;
    value ^= value >> 33U;
    value *= 0xc4ceb9fe1a85ec53uLL;
    value ^= value >> 33U;
    return (size_t) value;
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

static inline size_t ptcFakeDnsNameKeyHash(const ptc_fake_dns_name_key_t *key)
{
    uint64_t hash = 1469598103934665603ULL;

    for (uint8_t i = 0; i < key->len; ++i)
    {
        hash ^= (uint8_t) key->name[i];
        hash *= 1099511628211ULL;
    }

    hash ^= key->len;
    hash *= 1099511628211ULL;
    return (size_t) hash;
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
    kPtcDefaultUdpIdleTimeoutMs = 300U * 1000U,

    kPtcWritePollInterval        = 1,
    kPtcDrainTimeoutMs           = 30U * 1000U,
    kPtcCloserPeerCloseTimeoutMs = 60U * 1000U,
    kPtcMaxDrainBytesTotal       = 16U * 1024U * 1024U,
    kPtcMaxDrains                = 4096U,

    /* Keeps fake-DNS's eager name-map and record index within a practical
     * per-node startup allocation (roughly 16 MiB on a 64-bit build). */
    kPtcFakeDnsMaxRecords = 262144U,

    /* RFC 791's minimum IPv4 MTU; below it lwIP's fragment size rounds to zero. */
    kPtcMinNetifMtu = 68U,

    /*
     * Upper bound on the TCP bytes one flow may retain while lwIP has not taken
     * or acknowledged them. `Pause` is advisory between tunnels - a neighbour may
     * already have a queued callback, may race the pause, or may simply be
     * defective - so the queue needs a real admission limit rather than a
     * cooperative one. Matches ConnectionToPackets' `max-pending-bytes`.
     */
    kPtcDefaultMaxPendingBytes = 262144U,
    kPtcMinMaxPendingBytes     = 1024U,
    kPtcMaxMaxPendingBytes     = 67108864U,

    /*
     * The byte limit alone does not bound memory. Every retained payload owns a
     * whole sbuf from its pool class whatever its length, so 262,144 one-byte
     * callbacks satisfy a 256 KiB byte limit while retaining on the order of a
     * gigabyte of pool storage plus one acknowledgement record each.
     *
     * Deliberately not a JSON setting: it bounds allocator overhead rather than
     * expressing a deployment policy, and `max-pending-bytes` remains the tunable
     * data limit. 1,024 entries is far above what a working flow queues.
     */
    kPtcMaxPendingEntries = 1024U,

    /* Initial slots for a TCP line's pause/acknowledgement queues. */
    kPtcRetainQueueCapacity = 8
};

typedef struct interface_route_context_s interface_route_context_t;
typedef struct ptc_tcp_drain_s           ptc_tcp_drain_t;

typedef enum ptc_line_kind_e
{
    kPtcLineKindNone = 0,
    kPtcLineKindTcp,
    kPtcLineKindUdp
} ptc_line_kind_t;

struct interface_route_context_s
{
    tunnel_t          *tunnel;
    struct netif       netif;
    struct tcp_pcb    *tcp_pcb;
    struct udp_pcb    *udp_pcb;
    ptc_udp_flow_map_t udp_flows;
    wid_t              packet_wid;
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

typedef struct ptc_fake_dns_result_s
{
    sbuf_t    *response;
    ip4_addr_t source;
    ip4_addr_t destination;
    bool       handled;
} ptc_fake_dns_result_t;

typedef struct ptc_tstate_s
{
    interface_route_context_t **routes_v4;
    uint32_t                    route_worker_count;
    uint32_t                    max_pending_bytes;
    uint32_t                    max_pending_entries;
    uint32_t                    udp_idle_timeout_ms;
    ptc_fake_dns_t              fake_dns;
    quiescence_gate_t           output_gate;
    quiescence_gate_t           next_gate;
    ptc_tcp_drain_t            *drains;
    uint32_t                    drain_bytes;
    uint32_t                    drain_count;
    wmutex_t                    owned_lines_lock;
    line_t                    **owned_lines;
    uint32_t                    owned_worker_count;
    atomic_bool                 stopping;
    bool                        lwip_resources_destroyed;
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

    wtimer_t *udp_idle_timer;
    /*
     * Exact bytes this line still owns for acknowledgement or retry: the sum of
     * `total` over every live `ack_queue` record. `pause_queue` alone is not that
     * number - a fully written buffer waits only in `ack_queue`, and a partially
     * written one has already been shifted, so its visible length shrank.
     */
    uint32_t           pending_bytes;
    uint32_t           rx_uncredited;
    uint32_t           read_paused_len;
    ptc_udp_flow_key_t udp_flow_key;
    ip_addr_t          udp_local_addr;
    ip_addr_t          udp_peer_addr;
    uint16_t           udp_local_port;
    uint16_t           udp_peer_port;
    line_t            *owned_prev;
    line_t            *owned_next;
    uint8_t            kind;
    bool               write_paused;
    bool               read_paused;
    bool               next_init_sent;
    bool               write_poll_armed;
    bool               write_retry_queued;
    bool               refused_retry_queued;
    bool               owned_registered;
    /* Set under LOCK_TCPIP_CORE() after a required owner-worker handoff is
     * refused. The existing owned-line registry is the allocation-free final
     * owner; the owner worker clears this flag while closing the line. */
    bool terminal_required;
} ptc_lstate_t;

typedef enum ptc_flush_result_e
{
    kPtcFlushComplete = 0,
    kPtcFlushRetryable,
    kPtcFlushTerminal
} ptc_flush_result_t;

typedef enum ptc_tcp_drain_adopt_result_e
{
    kPtcTcpDrainNotNeeded = 0,
    kPtcTcpDrainAdopted,
    kPtcTcpDrainFailed
} ptc_tcp_drain_adopt_result_t;

typedef struct my_custom_pbuf
{
    struct pbuf_custom p;
    sbuf_t            *sbuf;
    buffer_pool_t     *origin_pool;
    wid_t              origin_wid;
} my_custom_pbuf_t;

LWIP_MEMPOOL_PROTOTYPE(RX_POOL);
enum
{
    kTunnelStateSize = sizeof(ptc_tstate_t),
    kLineStateSize   = sizeof(ptc_lstate_t)
};

WW_EXPORT void         ptcTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *ptcTunnelCreate(node_t *node);
WW_EXPORT api_result_t ptcTunnelApi(tunnel_t *instance, sbuf_t *message);

void ptcTunnelOnStart(tunnel_t *t);
void ptcTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void ptcTunnelOnQuiesceWait(tunnel_t *t, const ww_lifecycle_context_t *context);
void ptcTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context);
void ptcTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);

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

/* Takes ownership of buf and emits it only while the quiesce gate is admitted. */
bool ptcEmitPacketBuffer(tunnel_t *t, line_t *packet_line, sbuf_t *buf);

/* False when the line could not be made usable; it took and released no reference. */
bool ptcLinestateInitialize(ptc_lstate_t *ls, tunnel_t *t, line_t *l, ptc_line_kind_t kind, void *pcb);
void ptcLinestateDestroy(ptc_lstate_t *ls);

err_t ptcNetifOutput(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr);

/* The Stop gate. Published before Stop waits for the core lock, so every
 * core-locked path can treat it as a barrier by rechecking under that lock. */
bool ptcTunnelIsStopping(tunnel_t *t);
/* Requires LOCK_TCPIP_CORE(). Returns true only when this call aborted a TCP pcb. */
bool ptcRequiredControlRefusedLocked(ptc_lstate_t *ls, const char *operation);
void ptcDrainTerminalLinesOnCurrentWorker(tunnel_t *t, wid_t wid);
bool ptcNextGateEnter(tunnel_t *t);
void ptcNextGateLeave(tunnel_t *t);

/* RX_POOL is process-global and may retain live pbufs across node lifetimes. */
void ptcRxWrapperPoolInitializeOnce(void);

void ptcDetachTcpPcbLocked(ptc_lstate_t *ls);
/* All receive-credit helpers require LOCK_TCPIP_CORE(). */
bool ptcReceiveCreditAccumulateLocked(ptc_lstate_t *ls, uint32_t amount);
void ptcReceiveCreditRollbackLocked(ptc_lstate_t *ls, uint32_t amount);
bool ptcPausedReadAccumulateLocked(ptc_lstate_t *ls, uint32_t amount);
bool ptcReturnReceiveCreditLocked(ptc_lstate_t *ls, uint32_t amount);
void ptcDetachUdpFlowLocked(ptc_lstate_t *ls);
void ptcOwnedLineRegister(ptc_lstate_t *ls);
void ptcOwnedLineUnregister(ptc_lstate_t *ls);
void ptcDetachOwnedLinePcbsLocked(tunnel_t *t);
void ptcDrainOwnedLinesOnCurrentWorker(tunnel_t *t, wid_t wid);
void ptcCloseLineForStop(tunnel_t *t, line_t *l);
void ptcCloseLineFromNetwork(tunnel_t *t, line_t *l);
void ptcCloseLineFromDownstream(tunnel_t *t, line_t *l);
/*
 * Sheds a flow whose retained bytes passed `max-pending-bytes`. The PCB is
 * reset rather than drained: the bounded closer exists to deliver bytes a
 * cooperating peer produced, and adopting an over-limit backlog into it would
 * move the same unbounded growth one queue further along.
 */
void ptcCloseLineOverPendingLimit(tunnel_t *t, line_t *l);
bool ptcArmUdpIdleOnOwnerThread(ptc_lstate_t *ls);
void ptcCancelUdpIdleTimer(ptc_lstate_t *ls);
bool ptcEnsureNextInit(tunnel_t *t, line_t *l, ptc_lstate_t *ls);
void ptcOpenLineTask(tunnel_t *t, line_t *l);
void ptcDeliverPayloadTask(tunnel_t *t, line_t *l, sbuf_t *buf);
void ptcCloseLineTask(tunnel_t *t, line_t *l);
void ptcResumeUpstreamTask(tunnel_t *t, line_t *l);
void ptcWriteRetryTask(tunnel_t *t, line_t *l);
void ptcRefusedDataRetryTask(tunnel_t *t, line_t *l);
bool ptcFakeDnsLoadSettings(ptc_tstate_t *ts, const cJSON *settings);
void ptcFakeDnsDestroy(ptc_tstate_t *ts);
/* True when fake DNS is enabled and this is the address it answers on. */
bool ptcFakeDnsOwnsDestination(tunnel_t *t, const ip4_addr_p_t *dest);
bool ptcFakeDnsShouldDropFragment(const ptc_fake_dns_t *dns, const ip4_addr_p_t *dest, uint8_t protocol,
                                  bool is_fragment);

/*
 * Optional integer settings are validated, not defaulted on error: only an
 * omitted key keeps `value_inout`. `json_path` names the field in the diagnostic.
 */
bool                  ptcLoadOptionalInteger(const cJSON *settings, const char *key, int64_t minimum, int64_t maximum,
                                             int64_t *value_inout, const char *json_path);
ptc_fake_dns_result_t ptcFakeDnsHandleIpv4UdpPacket(tunnel_t *t, line_t *packet_line, sbuf_t *buf,
                                                    const struct ip_hdr *iphdr, const struct udp_hdr *udphdr);

/*
 * Publishes one built fake-DNS reply through the worker netif, fragmenting at
 * the inherited core MTU when it does not fit. Requires LOCK_TCPIP_CORE(); the
 * netif output callback only queues, so no neighbour callback runs inside it.
 * Returns false when nothing was published and the caller still owns the buffer.
 */
/* Consumes response on success and failure. */
bool  ptcFakeDnsPublishResponseLocked(tunnel_t *t, line_t *packet_line, sbuf_t *response, const ip4_addr_t *source,
                                      const ip4_addr_t *destination);
bool  ptcFakeDnsApplyMappedDestination(tunnel_t *t, address_context_t *dest_ctx, const ip_addr_t *ip, uint16_t port,
                                       uint8_t protocol);
err_t ptcEnsureTcpListener(interface_route_context_t *route_ctx, tunnel_t *t, const ip_addr_t *dest_ip,
                           uint16_t dest_port);
err_t ptcEnsureUdpListener(interface_route_context_t *route_ctx, tunnel_t *t, const ip_addr_t *dest_ip,
                           uint16_t dest_port);
interface_route_context_t *ptcFindOrCreateRouteContextV4(tunnel_t *t, wid_t packet_wid, const ip4_addr_t *dest_ip);
void                       ptcDestroyRouteContexts(tunnel_t *t);
void                       ptcDestroyLwipResources(tunnel_t *t);

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

ptc_flush_result_t ptcFlushWriteQueue(ptc_lstate_t *lstate);
void               ptcPauseQueuePushBack(ptc_lstate_t *lstate, sbuf_t *buf);
void               ptcPauseQueuePushFront(ptc_lstate_t *lstate, sbuf_t *buf);

/*
 * The only two places an acknowledgement record may enter or leave a line, so
 * `pending_bytes` stays exact without every caller remembering to adjust it.
 * Both require LOCK_TCPIP_CORE(), like the queues they maintain.
 */
void ptcAckQueuePushBack(ptc_lstate_t *lstate, sbuf_t *buf, uint32_t total);
void ptcAckQueuePopFront(ptc_lstate_t *lstate);

/*
 * Reserves the one acknowledgement slot and the one pause slot a payload can
 * need, so that every later insertion on this path is infallible. Returns false
 * without changing anything when the reservation could not be made; the caller
 * still owns its buffer and must shed only this flow.
 */
bool ptcReserveWriteSlots(ptc_lstate_t *lstate);

/*
 * Unwritten payloads occupy a contiguous suffix of `ack_queue` in `pause_queue`
 * order, so the record owning a paused buffer is found by index rather than by
 * searching. Both require LOCK_TCPIP_CORE().
 */
size_t      ptcFrontPauseAckIndexOf(const ptc_lstate_t *lstate);
sbuf_ack_t *ptcPauseAckRecordAt(ptc_lstate_t *lstate, size_t index);

/* True when this line already retains the node's maximum payload count. */
bool ptcPendingEntriesExhausted(const ptc_tstate_t *tstate, const ptc_lstate_t *lstate);

/*
 * True when `len` more retained bytes would pass the node's per-flow limit.
 * Overflow-safe: it never adds to `pending_bytes`, and it treats a counter that
 * has somehow passed the limit as full rather than trusting the subtraction.
 */
bool  ptcPendingBytesWouldOverflow(const ptc_tstate_t *tstate, const ptc_lstate_t *lstate, uint32_t len);
err_t ptcTcpSendCompleteCallback(void *arg, struct tcp_pcb *tpcb, u16_t len);
err_t ptcTcpPollCallback(void *arg, struct tcp_pcb *tpcb);
err_t ptcTcpSendFinLocked(struct tcp_pcb *pcb);
ptc_tcp_drain_adopt_result_t ptcTcpDrainAdoptLocked(tunnel_t *t, ptc_lstate_t *ls, bool *out_aborted);
void                         ptcTcpDrainDestroyAllLocked(tunnel_t *t);
