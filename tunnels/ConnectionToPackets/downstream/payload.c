#include "structure.h"

#include "loggers/network_logger.h"

/* Routing identity for one complete return packet; fragments are classified
 * only to reject them before transport parsing or worker handoff. */
typedef struct ctp_packet_view_s
{
    ctp_flow_key_t flow_key;
    bool           is_fragment;
} ctp_packet_view_t;

/*
 * One validated return packet on its way to the worker that owns its flow.
 *
 * Only plain data crosses the worker boundary: the tuple, the generation it was
 * matched under, and the bytes. No line or line-state pointer is retained, so a
 * flow retired between lookup and delivery simply fails the revalidation.
 *
 * The tuple and generation are copied from the synchronized flow registry
 * before the detached bytes are queued to the normal line's owner engine.
 */
typedef struct ctp_inject_msg_s
{
    /*
     * First member on purpose: lwIP hands the custom free callback a `struct
     * pbuf *`, and this is what turns it back into the message. `pbuf_custom`
     * itself starts with the pbuf, so the three addresses coincide.
     */
    struct pbuf_custom pbuf;

    ctp_handoff_budget_t *budget;
    size_t                charge;

    tunnel_t      *tunnel;
    ctp_flow_key_t key;
    uint64_t       generation;
    uint32_t       len;
    wid_t          wid;

    /*
     * pbuf_alloced_custom() leaves payload alignment to its caller. Explicit
     * alignment keeps typed IP/TCP header and checksum reads valid regardless
     * of the scalar routing metadata preceding these bytes.
     */
    _Alignas(MEM_ALIGNMENT) uint8_t data[];
} ctp_inject_msg_t;

/*
 * `_Alignas` above fixes the offset within the struct; ctpAllocatePacketMessage()
 * is what makes the struct's own address 16-aligned. Both halves are needed, and
 * this is the half a later field reordering could silently undo.
 */
_Static_assert(offsetof(ctp_inject_msg_t, data) % MEM_ALIGNMENT == 0,
               "the injected packet payload must start on a MEM_ALIGNMENT boundary");

static void ctpInjectMessageDestroy(void *payload)
{
    ctp_inject_msg_t     *msg    = payload;
    ctp_handoff_budget_t *budget = msg->budget;
    const size_t          charge = msg->charge;
    memoryFreeAligned(msg);
    ctpHandoffRelease(budget, charge);
}

/*
 * Called by lwIP when it is finished with an injected packet, possibly from its
 * owner-loop timer dispatch and possibly seconds later when TCP keeps an
 * out-of-order segment or refuses delivery until resources become available.
 * The message came from the global allocator rather than a worker-local pool
 * precisely so any thread may release it.
 */
static void ctpInjectPbufFree(struct pbuf *p)
{
    ctpInjectMessageDestroy(p);
}

static void ctpInjectPacketCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard           reason;
    discard           arg2;
    discard           arg3;
    ctp_inject_msg_t *msg = arg1;
    tunnel_t         *t   = msg->tunnel;
    if (t != NULL && currentThreadOwnsWorker(msg->wid))
        ctpDrainTerminalLinesOnCurrentWorker(t, msg->wid);
    ctpInjectMessageDestroy(msg);
}

static void ctpInjectPacketOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    ctp_inject_msg_t *msg = arg1;
    tunnel_t         *t   = msg->tunnel;
    ctp_tstate_t     *ts  = tunnelGetState(t);

    assert(currentThreadOwnsWorker(worker->wid) && msg->wid == worker->wid);
    /* Lookup is repeated on the application owner. The registry lock is
     * released before selecting the engine and delivering any packet. */
    bool handed_to_lwip = false;
    bool exact_netif    = false;

    ctp_netif_ctx_t *ctx = (ts->netifs != NULL && worker->wid < ts->netifs_count) ? ts->netifs[worker->wid] : NULL;
    if (ctx != NULL && ctx->added && ctx->tunnel == t && ctx->wid == worker->wid &&
        wwLwipEngineOwnerIsCurrent(worker->wid, getWorkerLoop(worker->wid)))
    {
        exact_netif = true;
    }

    if (exact_netif && ! atomicLoadRelaxed(&ts->stopping) &&
        ctpFlowStillOwns(t, &msg->key, msg->generation, worker->wid))
    {

        /* The detached allocation supplies one aligned custom pbuf. Its
         * bytes and handoff charge remain owned until the stack releases it. */
        msg->pbuf.custom_free_function = ctpInjectPbufFree;

        struct pbuf *p =
            pbuf_alloced_custom(PBUF_RAW, (u16_t) msg->len, PBUF_REF, &msg->pbuf, msg->data, (u16_t) msg->len);

        if (p == NULL)
        {
            LOGD("ConnectionToPackets: dropping a return packet, lwIP is out of pbufs");
        }
        else
        {
            /* input may synchronously free the custom pbuf and `msg`. */
            msg->tunnel    = NULL;
            handed_to_lwip = true;

            const err_t input_result = (err_t) wwLwipEngineInput(ctx->engine, p, &ctx->netif);
            if (input_result != ERR_OK)
            {
                pbuf_free(p);
            }
        }
    }

    ctpDrainTerminalLinesOnCurrentWorker(t, worker->wid);

    if (! handed_to_lwip)
    {
        ctpInjectMessageDestroy(msg);
    }
}

static bool ctpInjectPublish(tunnel_t *t, const ctp_flow_key_t *flow_key, uint64_t generation, wid_t wid,
                             ctp_inject_msg_t *msg)
{
    msg->tunnel     = t;
    msg->key        = *flow_key;
    msg->generation = generation;
    msg->wid        = wid;

    /*
     * Always queued, even when the owner is this worker: injecting inline would
     * run lwIP - and any pool work its receive callback triggers - inside the
     * packet line's own callback frame, possibly inside another engine.
     * The cleanup callback releases the message if the queue refuses it.
     */
    if (sendWorkerMessageForceQueueRetainOnRefusal(
            wid, (WorkerMessageCallback) ctpInjectPacketOnWorker, ctpInjectPacketCleanup, msg, NULL, NULL) ==
        kWorkerMessageSubmitAccepted)
    {
        return true;
    }

    ctpInjectMessageDestroy(msg);
    return false;
}

static bool ctpValidateIpv4Packet(const uint8_t *packet, uint32_t packet_len, const struct ip_hdr *iphdr,
                                  uint32_t *out_header_len)
{
    discard packet;

    if (UNLIKELY(packet_len < sizeof(struct ip_hdr) || IPH_V(iphdr) != 4))
    {
        return false;
    }

    const uint32_t header_len = IPH_HL_BYTES(iphdr);
    if (UNLIKELY(header_len < sizeof(struct ip_hdr) || header_len > packet_len))
    {
        return false;
    }

    // The buffer must describe exactly one packet: a mismatch would make the
    // transport ports read below meaningless.
    if (UNLIKELY(lwip_ntohs(IPH_LEN(iphdr)) != packet_len))
    {
        return false;
    }

    /*
     * Checked here rather than left to lwIP. ip4_input() drops a packet whose
     * header checksum fails. Reject corrupt return input before looking up a
     * flow or queueing detached bytes to its owner.
     */
    if (UNLIKELY(inet_chksum(iphdr, (u16_t) header_len) != 0))
    {
        return false;
    }

    *out_header_len = header_len;
    return true;
}

/* Classify one IPv4 return packet. Fragments are identified for the public
 * ingress drop before any transport-header access or owner handoff. */
static bool ctpBuildPacketView(tunnel_t *t, const uint8_t *packet, uint32_t packet_len, ctp_packet_view_t *out_view)
{
    ctp_tstate_t        *ts    = tunnelGetState(t);
    const struct ip_hdr *iphdr = (const struct ip_hdr *) packet;
    uint32_t             header_len;

    if (! ctpValidateIpv4Packet(packet, packet_len, iphdr, &header_len))
    {
        return false;
    }

    const uint8_t protocol = IPH_PROTO(iphdr);
    if (protocol != IP_PROTO_TCP && protocol != IP_PROTO_UDP)
    {
        return false;
    }

    if (iphdr->dest.addr != ip4_addr_get_u32(&ts->source_ip))
    {
        return false;
    }

    const uint16_t offset_field = lwip_ntohs(IPH_OFFSET(iphdr));

    if ((offset_field & IP_RF) != 0)
    {
        // The reserved flag has no defined meaning; a packet setting it is
        // malformed rather than something to guess about.
        return false;
    }

    const bool more_fragments = (offset_field & IP_MF) != 0;
    const bool has_offset     = (offset_field & IP_OFFMASK) != 0;
    const bool is_fragment    = more_fragments || has_offset;

    if ((offset_field & IP_DF) != 0 && is_fragment)
    {
        // "Don't fragment" on something that is itself a fragment is a
        // contradiction, and a common shape for crafted traffic.
        return false;
    }

    *out_view = (ctp_packet_view_t) {.is_fragment = is_fragment};
    if (is_fragment)
        return true;

    const uint32_t transport_len = packet_len - header_len;
    const uint32_t min_transport = protocol == IP_PROTO_TCP ? TCP_HLEN : UDP_HLEN;
    if (transport_len < min_transport)
        return false;

    const uint8_t *transport = ((const uint8_t *) iphdr) + header_len;

    out_view->flow_key = (ctp_flow_key_t) {
        .remote_addr_network = iphdr->src.addr,
        .local_addr_network  = iphdr->dest.addr,
        .remote_port         = (uint16_t) ((transport[0] << 8) | transport[1]),
        .local_port          = (uint16_t) ((transport[2] << 8) | transport[3]),
        .protocol            = protocol,
    };

    return true;
}

/*
 * The message and its payload are one allocation, aligned as a whole so that
 * `data` - already at a MEM_ALIGNMENT-multiple offset - lands on a boundary lwIP
 * may assume. `sizeof(*msg)` is deliberately not used for the size: the struct
 * is padded up to its own alignment, and offsetof() is what the payload actually
 * starts at.
 */
static ctp_inject_msg_t *ctpAllocatePacketMessage(ctp_handoff_budget_t *budget, uint32_t len)
{
    // An IPv4 packet cannot exceed this, and pbuf_alloced_custom() takes a
    // u16_t length, so a larger value could never be injected anyway. Checking
    // it here is also what keeps the size arithmetic below from wrapping.
    if (UNLIKELY(len == 0 || len > (uint32_t) UINT16_MAX))
    {
        return NULL;
    }

    const size_t size   = offsetof(ctp_inject_msg_t, data) + (size_t) len;
    const size_t charge = size + max((size_t) MEM_ALIGNMENT, sizeof(void *));
    if (! ctpHandoffReserve(budget, charge, true))
        return NULL;
    ctp_inject_msg_t *msg = memoryAllocateAligned(size, MEM_ALIGNMENT);

    assert(((uintptr_t) msg->data % MEM_ALIGNMENT) == 0);

    msg->tunnel = NULL;
    msg->budget = budget;
    msg->charge = charge;
    msg->len    = len;
    return msg;
}

/*
 * A return packet arriving on a worker packet line.
 *
 * This callback only validates/copies bytes and consults the synchronized
 * registry. Injection always queues to the normal line's owner engine.
 */
void ctpTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    const bool recalculate_checksum = packettunnelTakeChecksumRequest(buf);

    if (UNLIKELY(! ctpLineIsPacketLine(t, l)))
    {
        // Normal lines are never forwarded to next, so next can only answer on a
        // packet line. Anything else means the chain contract was violated.
        LOGF("ConnectionToPackets: downstream Payload arrived on a normal line");
        abortProgramNow(1);
        return;
    }

    ctp_packet_view_t view;

    if (UNLIKELY(! ctpPacketIngressGateEnter(t)))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    /* Copy into the aligned injection allocation before any typed packet access. */
    ctp_tstate_t     *ts  = tunnelGetState(t);
    ctp_inject_msg_t *msg = ctpAllocatePacketMessage(ts->handoff_budget, sbufGetLength(buf));
    if (UNLIKELY(msg == NULL))
    {
        lineReuseBuffer(l, buf);
        ctpPacketIngressGateLeave(t);
        return;
    }
    memoryCopy(msg->data, sbufGetRawPtr(buf), msg->len);

    if (UNLIKELY(! packettunnelFinalizeChecksumRequest(recalculate_checksum, msg->data, msg->len)))
    {
        lineReuseBuffer(l, buf);
        ctpInjectMessageDestroy(msg);
        ctpPacketIngressGateLeave(t);
        return;
    }

    if (! ctpBuildPacketView(t, msg->data, msg->len, &view))
    {
        lineReuseBuffer(l, buf);
        ctpInjectMessageDestroy(msg);
        ctpPacketIngressGateLeave(t);
        return;
    }

    if (UNLIKELY(view.is_fragment))
    {
        if (atomicIncU64Relaxed(&ts->fragment_drops) == 0)
            LOGW("ConnectionToPackets: dropping unsupported IPv4 fragments; enable reassembly at packet "
                 "ingress or reassemble before this node (further drops counted silently)");
        lineReuseBuffer(l, buf);
        ctpInjectMessageDestroy(msg);
        ctpPacketIngressGateLeave(t);
        return;
    }

    // The packet-line buffer belongs to this worker's pool and must not travel.
    lineReuseBuffer(l, buf);

    wid_t    owner_wid  = 0;
    uint64_t generation = 0;

    if (! ctpFlowLookup(t, &view.flow_key, &owner_wid, &generation))
    {
        LOGD("ConnectionToPackets: dropping a return packet that matches no registered flow");
        ctpInjectMessageDestroy(msg);
        ctpPacketIngressGateLeave(t);
        return;
    }

    discard ctpInjectPublish(t, &view.flow_key, generation, owner_wid, msg);
    ctpPacketIngressGateLeave(t);
}
