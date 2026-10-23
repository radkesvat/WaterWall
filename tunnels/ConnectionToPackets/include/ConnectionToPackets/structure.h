#pragma once

#include "wwapi.h"

#include "DomainResolver/interface.h"

#include "lwip/priv/tcp_priv.h"

/*
 * ConnectionToPackets is the active-open inverse of PacketsToConnection.
 *
 * A borrowed layer-4 line arriving from `prev` is opened as a userspace lwIP
 * TCP/UDP flow whose raw IPv4 packets leave through `next` on the chain's
 * per-worker packet lines; return packets arriving on those packet lines are
 * injected back into the owning flow's netif.
 *
 * The node is IPv4-only by design rather than pending IPv6 support: it exists to
 * bridge into packet topologies whose far side is an IPv4 stack, and an IPv6
 * destination is refused at configuration time where possible and at line
 * initialization otherwise.
 *
 * Two line roles reach this tunnel and they are never interchangeable:
 *
 *   normal line  - borrowed from the preceding listener/adapter. This node
 *                  initializes and destroys only its own line state and never
 *                  calls lineDestroy().
 *   packet line  - owned by tunnel_chain_t, persistent, never destroyed here.
 *
 * Every callback that can observe both must classify with
 * tunnelchainIsWorkerPacketLine() before touching line state.
 */

typedef struct ctp_netif_ctx_s ctp_netif_ctx_t;
typedef struct ctp_lstate_s    ctp_lstate_t;
typedef struct ctp_tcp_drain_s ctp_tcp_drain_t;

enum
{
    kCtpHandoffMaxBytes   = 16U * 1024U * 1024U,
    kCtpHandoffMaxEntries = 4096U
};

/* Shared by both packet directions. Every message retains this object until
 * its allocation is freed, including custom pbufs outliving tunnel teardown. */
typedef struct ctp_handoff_budget_s
{
    wmutex_t lock;
    size_t   max_bytes, max_entries;
    size_t   bytes, entries;
    uint64_t ingress_refused, egress_refused;
    bool     detached;
} ctp_handoff_budget_t;

ctp_handoff_budget_t *ctpHandoffBudgetCreate(size_t max_bytes, size_t max_entries);
bool                  ctpHandoffReserve(ctp_handoff_budget_t *budget, size_t charge, bool ingress);
void                  ctpHandoffRelease(ctp_handoff_budget_t *budget, size_t charge);
void                  ctpHandoffBudgetDetach(ctp_handoff_budget_t *budget);

typedef enum ctp_line_kind_e
{
    kCtpLineKindNone = 0,
    kCtpLineKindTcp,
    kCtpLineKindUdp
} ctp_line_kind_t;

/*
 * The exact tuple an inbound packet of this flow must carry, in the direction
 * it arrives from the network. The node is IPv4 only, so the address family is
 * implicit. Addresses are kept in network byte order and ports in host order,
 * matching the lwIP pcb fields they are built from.
 */
typedef struct ctp_flow_key_s
{
    uint32_t remote_addr_network;
    uint32_t local_addr_network;
    uint16_t remote_port;
    uint16_t local_port;
    uint8_t  protocol;
} ctp_flow_key_t;

/*
 * A registry entry. Its fields are protected by flows_lock. Packet workers
 * copy routing identity only; PCB/line pointers are used solely by their owner
 * engine. Release flows_lock before stack entry, output, or worker publication.
 *
 * `pcb` is retained only while this node may still touch it. A gracefully
 * closing connected flow transfers it from line state to a node-owned closer,
 * keeps the entry registered as draining through byte delivery, FIN-pending and
 * peer-close phases, and clears it only when the closer synchronously releases
 * the PCB. The entry then becomes a tombstone so late packets still find the
 * right worker and netif without exposing a stale PCB pointer.
 *
 * `expires_at_ms` bounds that tombstone. It is a routing grace period, not a
 * model of how long lwIP owns the pcb: the closer's TX-only shutdown moves the
 * pcb through FIN_WAIT or LAST_ACK before TIME_WAIT even starts, so no fixed
 * interval measured from retirement can track the real pcb lifetime. Tombstones are swept
 * in bulk when a new flow registers rather than by one timer each, because a
 * timer per close made shutdown cost scale with connection churn.
 *
 * `generation` distinguishes a delayed packet of an old flow from a new flow
 * that reused the same tuple *while that packet was queued*. It cannot identify
 * a packet that arrives from the network after the tuple was retired and reused,
 * because an IP packet carries no generation. That limitation is accepted, which
 * is why a registration that lands on a tombstone replaces it rather than being
 * refused: lwIP has already chosen that exact local port, and failing the flow
 * open would trade a rare late-packet ambiguity for a visible connection error.
 *
 * `lstate` is the live line state that owns `pcb`, and it is what lets stop-time
 * teardown clear the line's copy of the pointer instead of leaving a freed pcb
 * address reachable from a line whose worker has not drained yet. It is cleared
 * the moment the entry stops being that line's, which is also when `pcb` goes.
 */
typedef struct ctp_flow_entry_s
{
    void         *pcb;
    ctp_lstate_t *lstate;
    uint64_t      generation;
    uint64_t      expires_at_ms; /* valid while detached */
    wid_t         wid;
    uint8_t       protocol;
    bool          detached;

    /*
     * A pcb that outlived its line and is still writing bytes the application
     * handed over before it finished. It is neither active nor a tombstone: the
     * line is gone, but this node still owns the pcb and must keep routing to it,
     * so it can never be evicted by tombstone pressure or by an expiry sweep.
     * It becomes an ordinary tombstone only after the closer has released its
     * PCB, either after the real FIN/peer-close transition or a bounded abort.
     */
    bool draining;
} ctp_flow_entry_t;

/*
 * One detached entry's place in the retirement order.
 *
 * The map cannot answer "which tombstone is oldest" without a scan, so the ring
 * carries that ordering separately. Deadlines are a fixed offset from each
 * close, which makes insertion order deadline order, so the front of the ring is
 * always both the oldest tombstone and the next one to expire.
 *
 * `generation` is what makes a record safe to act on later: a tuple can be
 * unregistered or taken over by a new flow while its record still sits in the
 * ring, and a stale record must never erase the live entry that replaced it.
 */
typedef struct ctp_tombstone_ref_s
{
    ctp_flow_key_t key;
    uint64_t       generation;
    uint64_t       expires_at_ms;
} ctp_tombstone_ref_t;

static inline size_t ctpFlowKeyHash(const ctp_flow_key_t *key)
{
    uint64_t value = (((uint64_t) key->remote_addr_network) << 32U) ^ key->local_addr_network;
    value ^= ((uint64_t) key->remote_port << 16U) ^ (uint64_t) key->local_port;
    value ^= ((uint64_t) key->protocol) << 48U;
    value ^= value >> 33U;
    value *= 0xff51afd7ed558ccduLL;
    value ^= value >> 33U;
    value *= 0xc4ceb9fe1a85ec53uLL;
    value ^= value >> 33U;
    return (size_t) value;
}

#define i_type ctp_flow_map_t   // NOLINT
#define i_key  ctp_flow_key_t   // NOLINT
#define i_val  ctp_flow_entry_t // NOLINT
#define i_hash ctpFlowKeyHash   // NOLINT
#define i_eq(x, y)                                                                                                     \
    ((x)->remote_addr_network == (y)->remote_addr_network && (x)->local_addr_network == (y)->local_addr_network &&     \
     (x)->remote_port == (y)->remote_port && (x)->local_port == (y)->local_port &&                                     \
     (x)->protocol == (y)->protocol) // NOLINT
#include "stc/hmap.h"
#undef i_eq
#undef i_hash
#undef i_val
#undef i_key
#undef i_type

enum
{
    kCtpMinMtu                  = 576U,
    kCtpMaxMtu                  = 9000U,
    kCtpDefaultConnectTimeoutMs = 30U * 1000U,
    kCtpDefaultMaxPendingBytes  = 256U * 1024U,
    kCtpMinMaxPendingBytes      = 1024U,
    kCtpMaxMaxPendingBytes      = 64U * 1024U * 1024U,
    /* Fixed headroom for already-delivered input; not a pool allocation size. */
    kCtpPendingDeliveryHeadroom = 1024U * 1024U,
    kCtpPendingQueueCapacity    = 8,

    /*
     * The byte limit alone does not bound memory. Every retained payload owns a
     * whole sbuf from its pool class, so 262,144 one-byte callbacks satisfy a
     * 256 KiB byte limit while retaining on the order of a gigabyte of pool
     * storage plus deque entries. This caps the allocation count as well.
     *
     * Not a JSON setting: it exists to bound allocator overhead, not to express
     * a deployment policy, and `max-pending-bytes` remains the tunable data
     * limit. 1,024 entries is far above what a working flow queues and far below
     * what an amplification attempt needs.
     */
    kCtpMaxPendingEntries = 1024U,
    kCtpDropLogIntervalMs = 5U * 1000U,

    /*
     * tcp_poll() ticks in units of lwIP's 500 ms coarse timer. Twice a second is
     * enough to pick a flow back up once memory pressure clears, and the callback
     * is only installed while a write is actually blocked.
     */
    kCtpWritePollInterval = 1,

    /*
     * How long a post-Finish closer may keep trying to hand its remaining bytes
     * to lwIP before the flow is aborted. It bounds a peer that stops reading:
     * without it, a stalled receiver would hold a pcb and a closer buffer for as
     * long as it liked.
     */
    kCtpDrainTimeoutMs = 30U * 1000U,

    /*
     * How long a closer then waits for the peer to finish its own half, measured
     * from the moment the FIN went out.
     *
     * A half-close lets the peer keep sending for as long as it likes, and lwIP
     * will not step in: tcp_slowtmr() only times out a pcb sitting in FIN_WAIT_2
     * when TF_RXCLOSED is set, and a TX-only shutdown deliberately leaves that
     * flag clear - which is exactly what keeps the peer's data from being reset.
     * So this node has to supply the bound itself, or a peer that acknowledges
     * the FIN and then goes quiet pins a pcb, a registry entry and a one-byte
     * netif index for the life of the process.
     *
     * 60 s matches the conventional FIN_WAIT_2 timeout (Linux's tcp_fin_timeout).
     */
    kCtpCloserPeerCloseTimeoutMs = 60U * 1000U,

    /*
     * Bytes all in-flight drains of one instance may hold at once. Each drain is
     * separately bounded by the per-line pending limit, but many lines can finish
     * with a full queue at the same moment, so the instance needs its own ceiling.
     * Past it the flow is reset, because a clean FIN after discarding accepted
     * bytes would falsely report a successful shorter stream.
     */
    kCtpMaxDrainBytesTotal = 16U * 1024U * 1024U,

    /*
     * How many closers may exist at once. A graceful close of a connected flow
     * takes one even with nothing queued, because the FIN still has to be sent
     * without resetting and the tuple has to keep routing the peer's ACKs, so
     * the count is bounded by concurrent closes rather than by queued bytes.
     *
     * Past it a connected flow is reset. An untracked TX shutdown would be
     * reset-free, but it would also leave a pcb nothing bounds: lwIP does not
     * time out a write-only half-close, so "stop tracking it" and "leak it" are
     * the same outcome. An empty line queue does not make the tracking optional
     * either - bytes already copied into lwIP can still be unacknowledged.
     */
    kCtpMaxDrains = 4096,

    /*
     * How long a gracefully closed flow's tuple keeps routing to its old worker
     * and netif, so lwIP still receives the FIN/ACK exchange it is waiting for.
     *
     * It is a grace period, not the pcb's lifetime: 2 * TCP_MSL is TIME_WAIT's
     * duration, and TIME_WAIT only begins once the FIN exchange gets there, so a
     * tombstone can outlive its pcb or expire before it. That is acceptable
     * because neither direction of the mismatch loses a live flow - an early
     * expiry drops late close traffic, a late one holds a map entry - and it is
     * bounded by kCtpMaxTombstones below.
     */
    kCtpFlowCloseGraceMs = (uint32_t) (2UL * TCP_MSL),

    /*
     * Tombstones are bounded independently of the active-flow target: connection
     * churn creates them at whatever rate connections close, and without a cap a
     * high-churn deployment would grow the registry far past its flow count.
     *
     * It is a hard bound, enforced by the fixed ring below rather than by an
     * age-based sweep. Sweeping alone could not hold it: more than this many
     * flows can close inside one grace period, leaving every tombstone too young
     * to remove while each later registration scanned an ever-larger map with the
     * registry lock held by its caller.
     */
    kCtpMaxTombstones = 4096,

    /*
     * The largest payload an IPv4 UDP datagram can carry. Beyond this the length
     * simply does not fit the wire format, so it is a hard rejection rather than
     * an MTU question - anything below it is fragmented instead.
     */
    kCtpUdpHeaderOverhead = IP_HLEN + UDP_HLEN,
    kCtpMaxUdpPayload     = 65535U - IP_HLEN - UDP_HLEN
};

/*
 * One ordinary lwIP netif per event worker. All of them carry the same
 * configured virtual source address: a flow is only ever injected into the
 * netif of the worker that owns its normal line, and every pcb is pinned to its
 * netif with tcp_bind_netif()/udp_bind_netif(), so lwIP never has to
 * disambiguate them by address.
 */
struct ctp_netif_ctx_s
{
    struct netif      netif;
    tunnel_t         *tunnel;
    wid_t             wid;
    bool              added;
    ww_lwip_engine_t *engine;
    ctp_tcp_drain_t  *drains;

    /*
     * The packet worker chosen for the datagram currently being fragmented.
     *
     * Packet-worker selection is flow-affine, but a fragment at a nonzero offset
     * has no ports to be affine on, and the shared hash falls back to the IPv4
     * identification for those - which would scatter one flow's datagrams across
     * workers and break any next node that pins a flow to one of them.
     *
     * ip4_frag() emits every fragment of one datagram in a single synchronous
     * loop inside the non-reentrant owner engine, and this netif belongs to one worker, so one
     * slot is enough: offset zero publishes the flow's worker here and the
     * fragments that immediately follow read it back.
     */
    uint16_t frag_ident;
    wid_t    frag_wid;
    bool     frag_wid_valid;
};

typedef struct ctp_tstate_s
{
    node_t        domain_resolver_node;
    tunnel_t     *domain_resolver_tunnel;
    struct cJSON *domain_resolver_settings;

    // [0 .. netifs_count), lazily populated, mutated only under the owner engine
    ctp_netif_ctx_t **netifs;
    wid_t             netifs_count;

    /* Intrusive, allocation-free terminal handoff indexed by owner worker. */
    line_t **terminal_lines;
    /* Active borrowed-line state; source owners retain line destruction. */
    ctp_lstate_t        **active_lines;
    ctp_handoff_budget_t *handoff_budget;

    wrwlock_t      flows_lock;
    ctp_flow_map_t flows;           /* protected by flows_lock */
    uint64_t       next_generation; /* protected by flows_lock; never zero */

    /*
     * Retirement order for detached entries, all under flows_lock. Heap rather
     * than inline: kCtpMaxTombstones records is a six-figure byte count that only
     * a running instance needs.
     */
    ctp_tombstone_ref_t *tombstones;
    uint32_t             tomb_head;  /* index of the oldest record */
    uint32_t             tomb_count; /* records in the ring, <= kCtpMaxTombstones */

    /* Worker-local netif drain lists share this short count/byte allowance. */
    wmutex_t drain_lock;
    uint32_t drain_bytes;
    uint32_t drain_count;

    /* An unset address or zero port inherits that field from the line. */
    address_context_t target_addr;
    ip4_addr_t        source_ip;
    uint32_t          mtu;
    uint32_t          connect_timeout_ms;
    uint32_t          max_pending_bytes;
    int               domain_strategy;

    quiescence_gate_t prev_gate;
    quiescence_gate_t next_gate;
    quiescence_gate_t packet_ingress_gate;
    atomic_bool       stopping;
    atomic_ullong     fragment_drops;
    bool              lwip_resources_destroyed;
    bool              flow_registry_initialized;
} ctp_tstate_t;

/*
 * Resolver-side scratch filled by the prepare hook before DNS runs, so protocol
 * selection and destination validation happen exactly once and before the pcb
 * is created.
 */
typedef struct ctp_domain_resolver_lstate_s
{
    uint8_t protocol;
} ctp_domain_resolver_lstate_t;

struct ctp_lstate_s
{
    tunnel_t         *tunnel;
    line_t           *line;
    ww_lwip_engine_t *engine;
    ctp_netif_ctx_t  *netif_ctx;
    ctp_lstate_t     *active_prev;
    ctp_lstate_t     *active_next;

    union {
        struct tcp_pcb *tcp_pcb; /* protected by the owner engine */
        struct udp_pcb *udp_pcb; /* protected by the owner engine */
    };

    // Application bytes that could not be handed to lwIP yet: either the flow is
    // still connecting or the send window is full.
    buffer_queue_t pending_queue;

    ctp_flow_key_t flow_key;   /* published once at open, read under flows_lock */
    uint64_t       generation; /* published once at open, read under flows_lock */

    /*
     * The active-open deadline, owned by this line's event worker and by nothing
     * else. It holds exactly one line reference, taken when it is armed and
     * released either by the callback or by whoever cancels it.
     *
     * It is a real timer rather than a delayed line task because a delayed task
     * cannot be cancelled: a successful connection would keep its message, and
     * the line allocation behind it, until the configured timeout elapsed - up to
     * the ~49.7 days a uint32_t millisecond count can express.
     */
    wtimer_t *connect_timer;

    uint64_t last_drop_log_ms;

    /*
     * Bytes copied out of lwIP but not yet returned with tcp_recved(). The
     * paused count is a subset; queued owner tasks make up the remainder. Both
     * move into the instance-owned closer during a re-entrant line finish.
     */
    uint32_t rx_uncredited;
    uint32_t read_paused_len;

    uint8_t kind;
    bool    flow_registered; /* protected by the owner engine */
    bool    connected;       // lwIP will accept payload for this flow
    bool    est_sent;        // Est was already reported toward prev
    bool    write_blocked;   // lwIP cannot take more bytes right now
    bool    write_paused;    // a Pause was sent toward prev and not yet resumed
    line_t *terminal_prev;
    line_t *terminal_next;
    bool    terminal_pending;
    bool    read_paused;      // prev cannot accept downstream payload right now
    bool    write_poll_armed; // a tcp_poll retry is installed for a blocked write

    /* Owner-local latch bounds queued retry tasks from poll and sent callbacks. */
    bool write_retry_queued;
};

enum
{
    kTunnelStateSize = sizeof(ctp_tstate_t),
    kLineStateSize   = sizeof(ctp_lstate_t)
};

WW_EXPORT void         ctpTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *ctpTunnelCreate(node_t *node);
WW_EXPORT api_result_t ctpTunnelApi(tunnel_t *instance, sbuf_t *message);

void ctpTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void ctpTunnelOnStart(tunnel_t *t);
void ctpQueueWorkerPacketInit(void *worker, void *arg1, void *arg2, void *arg3);
void ctpTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void ctpTunnelOnQuiesceWait(tunnel_t *t, const ww_lifecycle_context_t *context);
void ctpTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context);
void ctpTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
bool ctpLoadSettings(ctp_tstate_t *ts, const cJSON *settings);

void ctpTunnelUpStreamInit(tunnel_t *t, line_t *l);
void ctpTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void ctpTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void ctpTunnelUpStreamPause(tunnel_t *t, line_t *l);
void ctpTunnelUpStreamResume(tunnel_t *t, line_t *l);

void ctpTunnelDownStreamEst(tunnel_t *t, line_t *l);
void ctpTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void ctpTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void ctpTunnelDownStreamPause(tunnel_t *t, line_t *l);
void ctpTunnelDownStreamResume(tunnel_t *t, line_t *l);

// ---------------------------------------------------------------------------
// common/line_state.c
// ---------------------------------------------------------------------------

/* Initializes state and retains one line reference until LinestateDestroy. */
void ctpLinestateInitialize(ctp_lstate_t *ls, tunnel_t *t, line_t *l, ctp_line_kind_t kind);
void ctpLinestateDestroy(ctp_lstate_t *ls);

// ---------------------------------------------------------------------------
// common/netif.c - per-worker netifs and the raw output path
// ---------------------------------------------------------------------------

ctp_netif_ctx_t *ctpEnsureNetifLocked(tunnel_t *t, wid_t wid);
void             ctpDestroyLwipResources(tunnel_t *t);
err_t            ctpNetifOutput(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr);

// ---------------------------------------------------------------------------
// common/flow.c - the tuple registry shared by every worker
// ---------------------------------------------------------------------------

bool ctpFlowRegistryInitialize(ctp_tstate_t *ts);
void ctpFlowRegistryDestroy(ctp_tstate_t *ts);
bool ctpFlowRegister(tunnel_t *t, ctp_lstate_t *ls, void *pcb, uint8_t protocol);
void ctpFlowUnregister(tunnel_t *t, ctp_lstate_t *ls);

/*
 * Hands a registry entry from a line to a drain and back again. Both run under
 * the owner engine, where every pcb transition already happens.
 */
void ctpFlowMarkDrainingLocked(tunnel_t *t, ctp_lstate_t *ls);
void ctpFlowRetireDrainLocked(tunnel_t *t, const ctp_flow_key_t *key, uint64_t generation, bool graceful);
bool ctpFlowLookup(tunnel_t *t, const ctp_flow_key_t *key, wid_t *out_wid, uint64_t *out_generation);
bool ctpFlowStillOwns(tunnel_t *t, const ctp_flow_key_t *key, uint64_t generation, wid_t wid);
void ctpDetachWorkerLines(tunnel_t *t, wid_t wid);
void ctpDestroyWorkerNetif(tunnel_t *t, wid_t wid);

// ---------------------------------------------------------------------------
// common/helpers.c - shared open/close/scheduling helpers
// ---------------------------------------------------------------------------

bool ctpSelectProtocol(tunnel_t *t, line_t *l, uint8_t *out_protocol);
bool ctpDomainResolverPrepare(tunnel_t *resolver, tunnel_t *owner, line_t *l, void *user_lstate);
/* Returns true only when this transition called tcp_abort(). */
bool ctpDetachFlowLocked(tunnel_t *t, ctp_lstate_t *ls, bool graceful);
void ctpCloseLineTowardPrev(tunnel_t *t, line_t *l);
/* Resets instead of draining; for admission failures, never for an application close. */
void ctpCloseLineTowardPrevWithoutDrain(tunnel_t *t, line_t *l);
void ctpCloseLineTask(tunnel_t *t, line_t *l);

/*
 * Both run on the line's owner event worker and nowhere else - that is what
 * makes the single line reference the timer holds safe to hand between the
 * callback and the canceller without any further synchronization.
 *
 * Cancelling is idempotent, so every teardown path may call it unconditionally.
 */
bool ctpArmConnectDeadline(tunnel_t *t, line_t *l, ctp_lstate_t *ls);
void ctpCancelConnectDeadline(ctp_lstate_t *ls);
void ctpDeliverPayloadTask(tunnel_t *t, line_t *l, sbuf_t *buf);
void ctpEstablishedTask(tunnel_t *t, line_t *l);
void ctpResumeWriteTask(tunnel_t *t, line_t *l);

/*
 * What one attempt at handing the pending queue to lwIP achieved.
 *
 * `ERR_MEM` is transient - lwIP is out of segments or pool memory and will have
 * room again - while anything else means this pcb can never accept these bytes.
 * Treating the two alike left a flow paused forever on the first and retried the
 * second until its deadline, so the caller has to be able to tell them apart.
 */
typedef enum ctp_flush_result_e
{
    kCtpFlushProgressed = 0, /* wrote something, or had nothing to write */
    kCtpFlushRetryable,      /* blocked on ERR_MEM or a closed send window */
    kCtpFlushTerminal        /* lwIP refused these bytes for good */
} ctp_flush_result_t;

ctp_flush_result_t ctpFlushPendingLocked(ctp_lstate_t *ls);
void               ctpApplyWriteBackpressure(tunnel_t *t, line_t *l);
bool               ctpTunnelIsStopping(tunnel_t *t);
bool               ctpLineIsPacketLine(tunnel_t *t, line_t *l);
bool               ctpPrevGateEnter(tunnel_t *t);
void               ctpPrevGateLeave(tunnel_t *t);
bool               ctpNextGateEnter(tunnel_t *t);
void               ctpNextGateLeave(tunnel_t *t);
bool               ctpPacketIngressGateEnter(tunnel_t *t);
void               ctpPacketIngressGateLeave(tunnel_t *t);
bool               ctpRequiredControlRefusedLocked(tunnel_t *t, ctp_lstate_t *ls, const char *operation);
void               ctpDrainTerminalLinesOnCurrentWorker(tunnel_t *t, wid_t wid);
void               ctpTerminalCancel(ctp_lstate_t *ls);

/*
 * The monotonic clock behind every deadline this node stores. It is callable
 * from any thread, unlike wloopNowMS().
 */
uint64_t ctpNowMs(void);

// ---------------------------------------------------------------------------
// common/tcp.c
// ---------------------------------------------------------------------------

bool            ctpTcpOpenFlow(tunnel_t *t, line_t *l, ctp_lstate_t *ls, const ip_addr_t *dest_ip, uint16_t dest_port);
struct tcp_pcb *ctpTcpDetachCallbacksLocked(ctp_lstate_t *ls);
bool            ctpTcpAbortFlowLocked(tunnel_t *t, ctp_lstate_t *ls);

/*
 * Closes the sending half without ever resetting.
 *
 * tcp_close() is not usable for a flow this node closes deliberately: in
 * ESTABLISHED or CLOSE_WAIT it sends RST and frees the pcb whenever the
 * application has not returned all receive credit - discarding outbound
 * segments the peer has not acknowledged yet. This node returns credit from an
 * owner-worker task, and deliberately withholds it while the previous tunnel is
 * paused, so that condition is ordinary rather than exceptional.
 *
 * tcp_shutdown(pcb, 0, 1) sends the FIN with no such rule. It is only defined
 * for the connected states, so anything else still goes through tcp_close(),
 * where the reset rule cannot apply because no data was ever received.
 *
 * Caller holds the owner engine. ERR_OK means lwIP accepted the request, not
 * necessarily that it allocated a FIN: TF_CLOSEPEND keeps the pcb in its
 * connected state until a timer retry succeeds. The closer therefore retains
 * callbacks and ownership until it observes the actual state transition.
 */
err_t ctpTcpSendFinLocked(struct tcp_pcb *pcb);
void  ctpTcpReturnReceiveCreditLocked(ctp_lstate_t *ls, uint32_t amount);
err_t ctpTcpConnectedCallback(void *arg, struct tcp_pcb *tpcb, err_t err);
err_t ctpTcpRecvCallback(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
err_t ctpTcpSentCallback(void *arg, struct tcp_pcb *tpcb, u16_t len);

/*
 * The retry source for a blocked write. Installed only while one is blocked, so
 * an idle flow installs no write-retry callback.
 */
err_t ctpTcpPollCallback(void *arg, struct tcp_pcb *tpcb);
void  ctpTcpErrorCallback(void *arg, err_t err);

// ---------------------------------------------------------------------------
// common/udp.c
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// common/drain.c - finishing a TCP flow that still owes the peer bytes
// ---------------------------------------------------------------------------

/*
 * Takes over `ls`'s pcb and whatever is left in its pending queue so the bytes
 * this node already accepted still reach the peer after the line is gone.
 *
 * Called under the owner engine from the graceful-close path, with the queue
 * already flushed as far as the send window allowed. The tri-state result says
 * whether no drain was needed, ownership transferred, or resource refusal
 * requires the caller to reset the flow.
 *
 * Nothing about the line survives the call: the bytes are copied out of their
 * worker-pool buffers, and no line, line-state or pool pointer is retained,
 * because the line's owner may destroy it the moment Finish returns.
 */
typedef enum ctp_tcp_drain_adopt_result_e
{
    kCtpTcpDrainNotNeeded = 0,
    kCtpTcpDrainAdopted,
    kCtpTcpDrainFailed
} ctp_tcp_drain_adopt_result_t;

ctp_tcp_drain_adopt_result_t ctpTcpDrainAdoptLocked(tunnel_t *t, ctp_lstate_t *ls, bool *out_aborted);

/* Owner stop aborts each detached PCB and releases its aggregate allowance. */
void ctpTcpDrainDestroyNetif(ctp_netif_ctx_t *ctx);
bool ctpDrainBudgetReserve(ctp_tstate_t *ts, uint32_t bytes);
void ctpDrainBudgetRelease(ctp_tstate_t *ts, uint32_t bytes);

// ---------------------------------------------------------------------------
// common/udp.c
// ---------------------------------------------------------------------------

bool            ctpUdpOpenFlow(tunnel_t *t, line_t *l, ctp_lstate_t *ls, const ip_addr_t *dest_ip, uint16_t dest_port);
struct udp_pcb *ctpUdpDetachCallbacksLocked(ctp_lstate_t *ls);
void            ctpUdpSendPayload(tunnel_t *t, line_t *l, ctp_lstate_t *ls, sbuf_t *buf);
void            ctpUdpRecvCallback(void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);
