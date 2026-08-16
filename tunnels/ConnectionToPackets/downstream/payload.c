#include "structure.h"

#include "devices/device_frag_settlement.h"

#include "loggers/network_logger.h"

/*
 * One validated return packet on its way to the worker that owns its flow.
 *
 * Only plain data crosses the worker boundary: the tuple, the generation it was
 * matched under, and the bytes. No line or line-state pointer is retained, so a
 * flow retired between lookup and delivery simply fails the revalidation.
 *
 * The tuple and generation are filled in at publish time rather than at
 * allocation: a fragment that arrives before fragment zero is copied here first
 * and only learns which flow it belongs to once fragment zero resolves it.
 */
typedef struct ctp_inject_msg_s
{
    /*
     * First member on purpose: lwIP hands the custom free callback a `struct
     * pbuf *`, and this is what turns it back into the message. `pbuf_custom`
     * itself starts with the pbuf, so the three addresses coincide.
     */
    struct pbuf_custom pbuf;

    tunnel_async_session_t *session;
    device_frag_claim_t    *claim;
    ctp_frag_key_t          claim_key;
    ctp_frag_key_t          delivery_key;
    ctp_flow_key_t          key;
    uint64_t                generation;
    uint64_t                delivery_serial;
    uint32_t                len;
    wid_t                   wid;
    bool                    has_delivery_token;

    /*
     * pbuf_alloced_custom() makes payload alignment the caller's problem, and
     * lwIP then reads this memory as `struct ip_hdr`, `struct tcp_hdr` and
     * u32_t checksum words. Without the specifier the ordinary field layout put
     * this at offset 68, so every injected packet handed lwIP a payload that
     * MEM_ALIGNMENT says cannot be relied on.
     */
    _Alignas(MEM_ALIGNMENT) uint8_t data[];
} ctp_inject_msg_t;

/*
 * A FIFO barrier queued behind every injection message for one completed or
 * poisoned datagram. It removes precisely that netif's lwIP reassembly object
 * before the outer association makes the IPv4 identification reusable.
 */
typedef struct ctp_frag_purge_msg_s
{
    tunnel_async_session_t *session;
    ctp_frag_key_t          key;
    uint64_t                serial;
} ctp_frag_purge_msg_t;

static bool ctpFragSchedulePurge(tunnel_t *t, const ctp_frag_key_t *frag_key, uint64_t serial, wid_t wid);

/*
 * `_Alignas` above fixes the offset within the struct; ctpAllocatePacketMessage()
 * is what makes the struct's own address 16-aligned. Both halves are needed, and
 * this is the half a later field reordering could silently undo.
 */
_Static_assert(offsetof(ctp_inject_msg_t, data) % MEM_ALIGNMENT == 0,
               "the injected packet payload must start on a MEM_ALIGNMENT boundary");

void ctpInjectMessageDestroy(void *payload)
{
    ctp_inject_msg_t *msg = payload;

    deviceFragClaimResolve(msg->claim, kDeviceFragSettlementUnknown);
    msg->claim = NULL;
    memoryFreeAligned(msg);
}

void ctpInjectMessageResolveNoResidue(void *payload)
{
    ctp_inject_msg_t *msg = payload;

    deviceFragClaimResolve(msg->claim, kDeviceFragSettlementNoResidue);
    msg->claim = NULL;
    memoryFreeAligned(msg);
}

/*
 * Called by lwIP when it is finished with an injected packet, possibly from its
 * own timer thread and possibly seconds later - a fragment waiting for
 * reassembly or a segment in TCP's out-of-order queue both hold one this long.
 * The message came from the global allocator rather than a worker-local pool
 * precisely so any thread may release it.
 */
static void ctpInjectPbufFree(struct pbuf *p)
{
    ctp_inject_msg_t *msg = (ctp_inject_msg_t *) p;
    assert(msg->claim == NULL);
    discard msg;
    ctpInjectMessageDestroy(p);
}

static void ctpInjectPacketCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard                 reason;
    discard                 arg2;
    discard                 arg3;
    ctp_inject_msg_t       *msg           = arg1;
    tunnel_async_session_t *session       = msg->session;
    tunnel_t               *t             = NULL;
    device_frag_claim_t    *settled_claim = NULL;

    if (tunnelasyncsessionEnter(session, &t))
    {
        if (currentThreadIsEventWorkerWID(msg->wid))
        {
            ctp_tstate_t *ts = tunnelGetState(t);

            LOCK_TCPIP_CORE();
            ctp_netif_ctx_t *ctx = (ts->netifs != NULL && msg->wid < ts->netifs_count) ? ts->netifs[msg->wid] : NULL;
            if (ctx != NULL && ctx->added && ctx->tunnel == t && ctx->wid == msg->wid && msg->claim != NULL)
            {
                discard ip4_reass_purge(&ctx->netif,
                                        &(ip4_addr_t) {.addr = msg->claim_key.remote_addr_network},
                                        &(ip4_addr_t) {.addr = msg->claim_key.local_addr_network},
                                        msg->claim_key.protocol,
                                        msg->claim_key.ident);
                settled_claim = msg->claim;
                msg->claim    = NULL;
            }
            UNLOCK_TCPIP_CORE();
            ctpDrainTerminalLinesOnCurrentWorker(t, msg->wid);
        }
        if (msg->has_delivery_token)
        {
            ctpFragSettleDelivery(t, &msg->delivery_key, msg->delivery_serial, false, ctpFragSchedulePurge);
        }
        tunnelasyncsessionLeave(session);
    }
    deviceFragClaimResolve(settled_claim, kDeviceFragSettlementNoResidue);
    tunnelasyncsessionUnref(session);
    ctpInjectMessageDestroy(msg);
}

static void ctpInjectPacketOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    ctp_inject_msg_t       *msg     = arg1;
    tunnel_async_session_t *session = msg->session;
    tunnel_t               *t       = NULL;

    if (! tunnelasyncsessionEnter(session, &t))
    {
        tunnelasyncsessionUnref(session);
        ctpInjectMessageDestroy(msg);
        return;
    }

    ctp_tstate_t *ts = tunnelGetState(t);

    LOCK_TCPIP_CORE();

    /*
     * Repeated under the core lock, and this is the check that actually counts.
     * lwIP's own error callback runs on the tcpip thread and can unregister and
     * free the pcb between the precheck above and here; injecting afterwards
     * would make the stack answer for a flow that no longer exists. The order is
     * the documented one - core lock outer, flows_lock inner - and it is safe
     * because this task is always queued and so never entered under a foreign
     * core lock.
     */
    bool handed_to_lwip  = false;
    bool claim_gate_held = false;
    bool exact_netif     = false;
    bool delivered       = false;

    const bool           has_delivery_token = msg->has_delivery_token;
    const ctp_frag_key_t delivery_key       = msg->delivery_key;
    const uint64_t       delivery_serial    = msg->delivery_serial;

    ctp_netif_ctx_t *ctx = (ts->netifs != NULL && worker->wid < ts->netifs_count) ? ts->netifs[worker->wid] : NULL;
    if (ctx != NULL && ctx->added && ctx->tunnel == t && ctx->wid == worker->wid)
    {
        exact_netif = true;
    }

    if (exact_netif && ! atomicLoadRelaxed(&ts->stopping) &&
        ctpFlowStillOwns(t, &msg->key, msg->generation, worker->wid) && deviceFragClaimBeginTakenStackUse(msg->claim))
    {
        claim_gate_held = msg->claim != NULL;

        /*
         * The message is wrapped rather than copied into a pool pbuf. That
         * removes the second full copy of every return packet, and it makes
         * each wire packet exactly one pbuf: lwIP charges reassembly against
         * `pbuf_clen()`, so a 9000-byte packet copied into 1500-byte pool
         * buffers used to consume six units of a budget expressed in
         * fragments.
         */
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
            device_frag_claim_t *claim     = msg->claim;
            const ctp_frag_key_t claim_key = msg->claim_key;
            msg->claim                     = NULL;
            handed_to_lwip                 = true;

            const err_t input_result = ctx->netif.input(p, &ctx->netif);
            delivered                = input_result == ERR_OK;
            if (input_result != ERR_OK)
            {
                pbuf_free(p);
                if (claim != NULL)
                {
                    discard ip4_reass_purge(&ctx->netif,
                                            &(ip4_addr_t) {.addr = claim_key.remote_addr_network},
                                            &(ip4_addr_t) {.addr = claim_key.local_addr_network},
                                            claim_key.protocol,
                                            claim_key.ident);
                }
            }

            if (claim != NULL)
            {
                const bool residue = ip4_reass_has(&ctx->netif,
                                                   &(ip4_addr_t) {.addr = claim_key.remote_addr_network},
                                                   &(ip4_addr_t) {.addr = claim_key.local_addr_network},
                                                   claim_key.protocol,
                                                   claim_key.ident);
                deviceFragClaimEndStackUse(claim);
                deviceFragClaimResolve(claim,
                                       residue ? kDeviceFragSettlementResiduePresent : kDeviceFragSettlementNoResidue);
            }
            claim_gate_held = false;
        }
    }

    if (! handed_to_lwip && msg->claim != NULL && exact_netif)
    {
        discard ip4_reass_purge(&ctx->netif,
                                &(ip4_addr_t) {.addr = msg->claim_key.remote_addr_network},
                                &(ip4_addr_t) {.addr = msg->claim_key.local_addr_network},
                                msg->claim_key.protocol,
                                msg->claim_key.ident);
        if (claim_gate_held)
        {
            deviceFragClaimEndStackUse(msg->claim);
        }
        deviceFragClaimResolve(msg->claim, kDeviceFragSettlementNoResidue);
        msg->claim = NULL;
    }

    UNLOCK_TCPIP_CORE();

    ctpDrainTerminalLinesOnCurrentWorker(t, worker->wid);

    if (has_delivery_token)
    {
        ctpFragSettleDelivery(t, &delivery_key, delivery_serial, delivered, ctpFragSchedulePurge);
    }

    tunnelasyncsessionLeave(session);
    tunnelasyncsessionUnref(session);

    if (! handed_to_lwip)
    {
        ctpInjectMessageDestroy(msg);
    }
}

static ctp_frag_publish_result_t ctpInjectPublish(tunnel_t *t, const ctp_flow_key_t *flow_key, uint64_t generation,
                                                  wid_t wid, const ctp_frag_key_t *frag_key, uint64_t serial,
                                                  void *payload)
{
    ctp_inject_msg_t *msg = payload;
    ctp_tstate_t     *ts  = tunnelGetState(t);

    msg->session    = ts->async_session;
    msg->key        = *flow_key;
    msg->generation = generation;
    msg->wid        = wid;
    if (frag_key != NULL)
    {
        msg->delivery_key       = *frag_key;
        msg->delivery_serial    = serial;
        msg->has_delivery_token = true;
    }
    tunnelasyncsessionRef(msg->session);

    /*
     * Always queued, even when the owner is this worker: injecting inline would
     * run lwIP - and any pool work its receive callback triggers - inside the
     * packet line's own callback frame, possibly under a foreign core lock.
     * The cleanup callback releases the message if the queue refuses it.
     */
    if (sendWorkerMessageForceQueueRetainOnRefusal(
            wid, (WorkerMessageCallback) ctpInjectPacketOnWorker, ctpInjectPacketCleanup, msg, NULL, NULL) ==
        kWorkerMessageSubmitAccepted)
    {
        return (ctp_frag_publish_result_t) {.accepted = true};
    }

    device_frag_claim_t *refused_claim = msg->claim;
    msg->claim                         = NULL;
    tunnelasyncsessionUnref(msg->session);
    memoryFreeAligned(msg);
    return (ctp_frag_publish_result_t) {.refused_receipt = refused_claim, .accepted = false};
}

static void ctpFragPurgeCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard               reason;
    discard               arg2;
    discard               arg3;
    ctp_frag_purge_msg_t *msg = arg1;
    tunnelasyncsessionUnref(msg->session);
    memoryFree(msg);
}

static void ctpFragPurgeOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    ctp_frag_purge_msg_t   *msg     = arg1;
    tunnel_async_session_t *session = msg->session;
    tunnel_t               *t       = NULL;

    if (! tunnelasyncsessionEnter(session, &t))
    {
        tunnelasyncsessionUnref(session);
        memoryFree(msg);
        return;
    }

    ctp_tstate_t *ts = tunnelGetState(t);

    LOCK_TCPIP_CORE();

    ctp_netif_ctx_t *ctx = (ts->netifs != NULL && worker->wid < ts->netifs_count) ? ts->netifs[worker->wid] : NULL;

    bool exact_absence = false;
    if (ctx != NULL && ctx->added && ctx->tunnel == t && ctx->wid == worker->wid)
    {
        ip4_addr_t source      = {.addr = msg->key.remote_addr_network};
        ip4_addr_t destination = {.addr = msg->key.local_addr_network};

        discard ip4_reass_purge(&ctx->netif, &source, &destination, msg->key.protocol, msg->key.ident);
        exact_absence = true;
    }

    UNLOCK_TCPIP_CORE();

    /*
     * Reached only after every earlier injection task for this datagram has
     * either handed its pbuf to lwIP or discarded it. If Stop removed the netif
     * first, its netif-wide purge supplied the same guarantee.
     */
    ctpFragRetirePurged(t, &msg->key, msg->serial, exact_absence);
    tunnelasyncsessionLeave(session);
    tunnelasyncsessionUnref(session);
    memoryFree(msg);
}

static bool ctpFragSchedulePurge(tunnel_t *t, const ctp_frag_key_t *frag_key, uint64_t serial, wid_t wid)
{
    ctp_frag_purge_msg_t *msg = memoryAllocate(sizeof(*msg));

    if (UNLIKELY(msg == NULL))
    {
        return false;
    }

    ctp_tstate_t *ts = tunnelGetState(t);
    *msg             = (ctp_frag_purge_msg_t) {
                    .session = ts->async_session,
                    .key     = *frag_key,
                    .serial  = serial,
    };
    tunnelasyncsessionRef(msg->session);

    return sendWorkerMessageForceQueueWithCleanup(
               wid, (WorkerMessageCallback) ctpFragPurgeOnWorker, ctpFragPurgeCleanup, msg, NULL, NULL) ==
           kWorkerMessageSubmitAccepted;
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
     * header checksum fails, so a corrupt fragment would otherwise be recorded
     * as coverage for a datagram the stack never received a byte of - and the
     * association would then retire on a completion that never happened.
     */
    if (UNLIKELY(inet_chksum(iphdr, (u16_t) header_len) != 0))
    {
        return false;
    }

    *out_header_len = header_len;
    return true;
}

/*
 * Classifies the packet and builds whichever keys it can carry.
 *
 * A return packet's source is the remote peer and its destination is this
 * node's virtual local endpoint, which is exactly the orientation the registry
 * key was published in. A fragment at a nonzero offset has no transport header
 * at all, so it is identified by the IPv4 reassembly tuple instead and routed
 * through the association table.
 */
bool ctpBuildPacketView(tunnel_t *t, const uint8_t *packet, uint32_t packet_len, ctp_packet_view_t *out_view)
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

    if (is_fragment && header_len != IP_HLEN)
    {
        // ip4_reass() refuses any fragment carrying IP options, so one accepted
        // here would occupy an association and record coverage for a datagram
        // lwIP is never going to assemble.
        return false;
    }

    *out_view = (ctp_packet_view_t) {
        .frag_key =
            {
                .remote_addr_network = iphdr->src.addr,
                .local_addr_network  = iphdr->dest.addr,
                .ident               = lwip_ntohs(IPH_ID(iphdr)),
                .protocol            = protocol,
            },
        .span =
            {
                // The offset field counts eight-byte units of transport payload.
                .offset      = (uint32_t) (offset_field & IP_OFFMASK) * 8U,
                .payload_len = packet_len - header_len,
                .is_first    = ! has_offset,
                .is_last     = ! more_fragments,
            },
        .is_fragment = is_fragment,
    };

    if (out_view->is_fragment && ! out_view->span.is_first)
    {
        // No transport header here; the association table supplies the flow.
        return true;
    }

    const uint32_t transport_len = packet_len - header_len;
    const uint32_t min_transport =
        out_view->is_fragment ? 4U : ((protocol == IP_PROTO_TCP) ? (uint32_t) TCP_HLEN : (uint32_t) UDP_HLEN);

    if (transport_len < min_transport)
    {
        return false;
    }

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
static ctp_inject_msg_t *ctpAllocatePacketMessage(uint32_t len)
{
    // An IPv4 packet cannot exceed this, and pbuf_alloced_custom() takes a
    // u16_t length, so a larger value could never be injected anyway. Checking
    // it here is also what keeps the size arithmetic below from wrapping.
    if (UNLIKELY(len == 0 || len > (uint32_t) UINT16_MAX))
    {
        return NULL;
    }

    ctp_inject_msg_t *msg = memoryAllocateAligned(offsetof(ctp_inject_msg_t, data) + (size_t) len, MEM_ALIGNMENT);

    if (UNLIKELY(msg == NULL))
    {
        return NULL;
    }

    assert(((uintptr_t) msg->data % MEM_ALIGNMENT) == 0);

    msg->claim              = NULL;
    msg->session            = NULL;
    msg->len                = len;
    msg->has_delivery_token = false;
    return msg;
}

/*
 * A return packet arriving on a worker packet line.
 *
 * Nothing here may touch lwIP. PacketsToConnection now defers publication
 * outside its core-locked frame, but an arbitrary neighboring packet node need
 * not make that promise. The tuple lookup therefore uses the registry's own
 * lock and injection is always handed to the owner worker.
 */
void ctpTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    const bool recalculate_checksum = packettunnelTakeChecksumRequest(l);

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

    if (UNLIKELY(! deviceFragClaimPacketMatches(buf)))
    {
        lineReuseBuffer(l, buf);
        ctpPacketIngressGateLeave(t);
        return;
    }

    /* Copy into the aligned injection allocation before any typed packet access. */
    ctp_inject_msg_t *msg = ctpAllocatePacketMessage(sbufGetLength(buf));
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

    msg->claim     = deviceFragClaimTake(buf);
    msg->claim_key = view.frag_key;

    // The packet-line buffer belongs to this worker's pool and must not travel.
    lineReuseBuffer(l, buf);

    wid_t    owner_wid  = 0;
    uint64_t generation = 0;

    if (! view.is_fragment && ! ctpFlowLookup(t, &view.flow_key, &owner_wid, &generation))
    {
        LOGD("ConnectionToPackets: dropping a return packet that matches no registered flow");
        ctpInjectMessageDestroy(msg);
        ctpPacketIngressGateLeave(t);
        return;
    }

    if (! view.is_fragment)
    {
        discard ctpInjectPublish(t, &view.flow_key, generation, owner_wid, NULL, 0, msg);
        ctpPacketIngressGateLeave(t);
        return;
    }

    /*
     * Fragments go through the association table instead: only offset zero
     * carries the ports the registry is keyed on, and every fragment of one
     * datagram has to reach the same worker for lwIP to reassemble it into that
     * worker's netif. The table takes ownership of `msg` either way, so its
     * length is read before handing it over.
     */
    const uint32_t packet_len = msg->len;

    ctpFragHandlePacket(t,
                        &view.frag_key,
                        &view.flow_key,
                        &view.span,
                        msg,
                        packet_len,
                        ctpInjectPublish,
                        ctpInjectMessageDestroy,
                        ctpFragSchedulePurge);
    ctpPacketIngressGateLeave(t);
}
