#include "structure.h"

#include "loggers/network_logger.h"

#include "loggers/log_rate_limiter.h"

enum
{
    kPtcRxPoolExhaustionLogIntervalMs = 5U * 1000U
};

static atomic_log_rate_limiter_t rx_pool_exhaustion_log;
static atomic_log_rate_limiter_t fake_dns_fragment_log;

static bool ptcPacketNeedsAlignedCopy(const sbuf_t *buf)
{
    return ((uintptr_t) sbufGetRawPtr(buf) % MEM_ALIGNMENT) != 0;
}

/*
 * One wrapper per pbuf this node hands to lwIP, held for as long as lwIP keeps
 * the pbuf: a fragment waiting for reassembly and a TCP segment waiting in the
 * out-of-order queue both pin one. The shared reassembly budget in lwipopts.h is
 * therefore the lower bound - a pool of 10 could not carry a single fragmented
 * 8 KiB datagram - and the headroom on top of it covers ordinary in-flight
 * traffic. Exhaustion drops the packet and is reported below, never fatal.
 */
LWIP_MEMPOOL_DECLARE(RX_POOL, WW_LWIP_RX_WRAPPER_POOL_SIZE, sizeof(my_custom_pbuf_t), "Zero-copy RX PBUF pool")

static wonce_t g_rx_pool_once = WONCE_INIT;

static void ptcRxWrapperPoolInitialize(void)
{
    LWIP_MEMPOOL_INIT(RX_POOL);
}

void ptcRxWrapperPoolInitializeOnce(void)
{
    wonce(&g_rx_pool_once, ptcRxWrapperPoolInitialize);
}

static void my_pbuf_free_custom(struct pbuf *p)
{
    my_custom_pbuf_t *custombuf = (my_custom_pbuf_t *) p;

    /*
     * TCP may retain this pbuf in its out-of-order queue and release it later
     * from the lwIP timer thread. Never infer ownership from the freeing
     * thread: that would return the buffer to the pseudo-worker's pool. A
     * foreign thread also cannot mutate the originating worker-local pool, so
     * it destroys the standalone allocation instead.
     */
    if (currentThreadIsEventWorkerWID(custombuf->origin_wid))
    {
        bufferpoolReuseBuffer(custombuf->origin_pool, custombuf->sbuf);
    }
    else
    {
        sbufDestroy(custombuf->sbuf);
    }
    LWIP_MEMPOOL_FREE(RX_POOL, custombuf);
}

/*
 * Copies a shifted packet into a buffer whose payload lwIP may read as typed
 * headers.
 *
 * A pooled buffer starts at its pool's configured left padding, which nothing
 * requires to be a MEM_ALIGNMENT multiple - so the best-fit buffer is checked
 * rather than assumed, and a zero-padding allocation is what guarantees the
 * property when it does not hold. Returns NULL only when the length is one no
 * buffer can carry.
 */
static sbuf_t *ptcAcquireAlignedCopy(buffer_pool_t *pool, sbuf_t *src)
{
    const uint32_t len = sbufGetLength(src);

    if (UNLIKELY(len == 0 || len > (uint32_t) UINT16_MAX))
    {
        return NULL;
    }

    sbuf_t *dst = bufferpoolGetBestFit(pool, len, 0);

    if (UNLIKELY(((uintptr_t) sbufGetMutablePtr(dst) % MEM_ALIGNMENT) != 0))
    {
        bufferpoolReuseBuffer(pool, dst);
        dst = sbufCreateWithPadding(len, 0);
    }

    assert(((uintptr_t) sbufGetMutablePtr(dst) % MEM_ALIGNMENT) == 0);

    sbufSetLength(dst, len);
    memoryCopyLarge(sbufGetMutablePtr(dst), sbufGetRawPtr(src), len);
    sbufTransferLifetime(src, dst);
    return dst;
}

/*
 * The reassembly identity of one IPv4 fragment.
 */
typedef struct ptc_fragment_key_s
{
    ip4_addr_t source;
    ip4_addr_t destination;
    uint16_t   identification;
    uint8_t    protocol;
} ptc_fragment_key_t;

/*
 * Reads the reassembly identity out of an IPv4 packet, if it has one.
 *
 * Only a fragment has reassembly state to purge, and only a fragment is ever
 * tracked by the device fragment table, so an unfragmented packet answers false
 * and every settlement path below becomes a no-op for it.
 */
static bool ptcReadFragmentKey(const sbuf_t *buf, ptc_fragment_key_t *out)
{
    const uint8_t *packet = sbufGetRawPtr(buf);
    const uint32_t length = sbufGetLength(buf);

    if (length < IP_HLEN || (packet[0] >> 4U) != 4)
    {
        return false;
    }

    const uint16_t fragment_bits = GET_BE16(packet + 6);
    if ((fragment_bits & (IP_MF | IP_OFFMASK)) == 0)
    {
        return false;
    }

    // Byte reads, because this runs before the alignment decision below.
    memoryCopy(&out->source.addr, packet + 12, sizeof(out->source.addr));
    memoryCopy(&out->destination.addr, packet + 16, sizeof(out->destination.addr));
    out->protocol       = packet[9];
    out->identification = GET_BE16(packet + 4);
    return true;
}

/*
 * Refuses a fragment and reports why the refusal is safe.
 *
 * Purging first is the whole point: an earlier fragment of this identity may
 * already sit in reassembly, and releasing the device's association while that
 * prefix survives is exactly how a later same-identification datagram completes
 * a hybrid. With the exact key gone, the identity holds nothing and can be
 * reused immediately. Called with LOCK_TCPIP_CORE() held, like every other
 * reassembly operation.
 */
static void ptcReportFragmentRefusalLocked(const ptc_fragment_key_t *key, struct netif *inp, sbuf_t *buf)
{
    discard ip4_reass_purge(inp, &key->source, &key->destination, key->protocol, key->identification);
    deviceFragClaimResolveBuffer(buf, kDeviceFragSettlementNoResidue);
}

static void ptcSubmitPacketToStack(sbuf_t *buf, struct netif *inp)
{
    // Runs on the packet line's event worker; record that identity with the
    // pbuf so a later lwIP-thread free knows whose pool the sbuf came from.
    const wid_t    origin_wid  = getCurrentEventWorkerWID();
    buffer_pool_t *origin_pool = getWorkerBufferPool(origin_wid);

    /*
     * Read before the buffer can change hands: on the aligned-copy path `buf` is
     * replaced, and on the success path lwIP owns it.
     */
    ptc_fragment_key_t fragment_key;
    const bool         is_fragment = ptcReadFragmentKey(buf, &fragment_key);

    if (UNLIKELY(! deviceFragClaimPacketMatches(buf)))
    {
        /* The receipt names the pre-transform identity, so a query of these
         * mutated bytes cannot factually settle it. Drop this copy and keep the
         * original identity quarantined as unknown. Purging the mutated key is
         * still useful if another corrupted copy reached lwIP first. */
        if (is_fragment)
        {
            discard ip4_reass_purge(inp,
                                    &fragment_key.source,
                                    &fragment_key.destination,
                                    fragment_key.protocol,
                                    fragment_key.identification);
        }
        deviceFragClaimResolveBuffer(buf, kDeviceFragSettlementUnknown);
        bufferpoolReuseBuffer(origin_pool, buf);
        return;
    }

    if (UNLIKELY(! deviceFragClaimMayEnterStack(buf)))
    {
        if (is_fragment)
        {
            ptcReportFragmentRefusalLocked(&fragment_key, inp, buf);
        }
        else
        {
            deviceFragClaimResolveBuffer(buf, kDeviceFragSettlementUnknown);
        }
        bufferpoolReuseBuffer(origin_pool, buf);
        return;
    }

    /*
     * Packet transforms may leave the sbuf cursor at any byte alignment. Keep
     * the zero-copy path for the common aligned case, but copy a shifted packet
     * into an aligned sbuf before the stack reads typed IP/TCP headers from it,
     * so it keeps travelling through the custom-pbuf wrapper. A PBUF_RAM copy
     * would land in lwIP's pooled heap, whose largest class caps a valid IPv4
     * packet at roughly 16 KiB - a ceiling the aligned path beside it does not
     * have. Alignment is a boundary responsibility here, not a new packet-chain
     * contract.
     */
    if (UNLIKELY(ptcPacketNeedsAlignedCopy(buf)))
    {
        /*
         * The copy goes into another sbuf and through the ordinary wrapper below,
         * not into a PBUF_RAM.
         *
         * With MEM_USE_POOLS the lwIP heap's largest class is 16 KiB including
         * allocator and pbuf overhead, so a PBUF_RAM copy silently dropped every
         * valid IPv4 packet above roughly that size - a ceiling the aligned path
         * beside it does not have, on a node whose input contract is full IPv4.
         * It also spent lwIP's TCP transmit heap on receive traffic.
         */
        sbuf_t *aligned = ptcAcquireAlignedCopy(origin_pool, buf);

        if (UNLIKELY(aligned == NULL))
        {
            if (is_fragment)
            {
                ptcReportFragmentRefusalLocked(&fragment_key, inp, buf);
            }
            bufferpoolReuseBuffer(origin_pool, buf);
            return;
        }

        bufferpoolReuseBuffer(origin_pool, buf);
        buf = aligned;
    }

    device_frag_claim_t *stack_claim = NULL;
    if (UNLIKELY(! deviceFragClaimBeginStackUse(buf, &stack_claim)))
    {
        if (is_fragment)
        {
            ptcReportFragmentRefusalLocked(&fragment_key, inp, buf);
        }
        else
        {
            deviceFragClaimResolveBuffer(buf, kDeviceFragSettlementUnknown);
        }
        bufferpoolReuseBuffer(origin_pool, buf);
        return;
    }

    my_custom_pbuf_t *custombuf = (my_custom_pbuf_t *) LWIP_MEMPOOL_ALLOC(RX_POOL);
    if (custombuf == NULL)
    {
        // Shared by every worker, so the gate has to be atomic. A silent drop
        // here used to be indistinguishable from a network loss.
        if (atomicLogRateLimiterShouldLog(&rx_pool_exhaustion_log, kPtcRxPoolExhaustionLogIntervalMs))
        {
            LOGW("PacketsToConnection: dropping a packet, the zero-copy RX wrapper pool (%d) is exhausted",
                 (int) WW_LWIP_RX_WRAPPER_POOL_SIZE);
        }
        deviceFragClaimEndStackUse(stack_claim);
        if (is_fragment)
        {
            ptcReportFragmentRefusalLocked(&fragment_key, inp, buf);
        }
        bufferpoolReuseBuffer(origin_pool, buf);
        return;
    }

    custombuf->p.custom_free_function = my_pbuf_free_custom;
    custombuf->sbuf                   = buf;
    custombuf->origin_pool            = origin_pool;
    custombuf->origin_wid             = origin_wid;

    /* The slow path above owns every valid misaligned cursor. */
    assert(((uintptr_t) sbufGetMutablePtr(buf) % MEM_ALIGNMENT) == 0);

    struct pbuf *p = pbuf_alloced_custom(
        PBUF_RAW, sbufGetLength(buf), PBUF_REF, &custombuf->p, sbufGetMutablePtr(buf), sbufGetLength(buf));
    if (p == NULL)
    {
        deviceFragClaimEndStackUse(stack_claim);
        if (is_fragment)
        {
            ptcReportFragmentRefusalLocked(&fragment_key, inp, buf);
        }
        bufferpoolReuseBuffer(origin_pool, buf);
        LWIP_MEMPOOL_FREE(RX_POOL, custombuf);
        return;
    }

    /* The pbuf may synchronously release its sbuf before input returns. Keep the
     * receipt separately until the exact post-input reassembly query is done. */
    device_frag_claim_t *claim = deviceFragClaimTake(buf);
    assert(claim == stack_claim);
    const err_t input_result = inp->input(p, inp);
    if (input_result != ERR_OK)
    {
        if (is_fragment)
        {
            discard ip4_reass_purge(inp,
                                    &fragment_key.source,
                                    &fragment_key.destination,
                                    fragment_key.protocol,
                                    fragment_key.identification);
            deviceFragClaimEndStackUse(stack_claim);
            deviceFragClaimResolve(claim, kDeviceFragSettlementNoResidue);
        }
        else
        {
            deviceFragClaimEndStackUse(stack_claim);
            deviceFragClaimResolve(claim, kDeviceFragSettlementUnknown);
        }
        pbuf_free(p);
        return;
    }

    if (is_fragment)
    {
        const bool residue = ip4_reass_has(
            inp, &fragment_key.source, &fragment_key.destination, fragment_key.protocol, fragment_key.identification);
        deviceFragClaimEndStackUse(stack_claim);
        deviceFragClaimResolve(claim, residue ? kDeviceFragSettlementResiduePresent : kDeviceFragSettlementNoResidue);
    }
    else
    {
        deviceFragClaimEndStackUse(stack_claim);
        deviceFragClaimResolve(claim, kDeviceFragSettlementUnknown);
    }
}

static bool ptcValidateIpv4Packet(const sbuf_t *buf, const struct ip_hdr *iphdr)
{
    const uint32_t packet_len = sbufGetLength(buf);

    if (UNLIKELY(packet_len < sizeof(struct ip_hdr) || IPH_V(iphdr) != 4))
    {
        return false;
    }

    const uint32_t header_len = IPH_HL_BYTES(iphdr);
    if (UNLIKELY(header_len < sizeof(struct ip_hdr) || header_len > packet_len))
    {
        return false;
    }

    const uint32_t total_len = lwip_ntohs(IPH_LEN(iphdr));
    if (UNLIKELY(total_len < header_len || total_len > packet_len))
    {
        return false;
    }

    return true;
}

static bool ptcPacketHasTransportHeader(const sbuf_t *buf, const struct ip_hdr *iphdr, uint32_t min_transport_len)
{
    const uint32_t header_len = IPH_HL_BYTES(iphdr);
    return sbufGetLength(buf) >= header_len + min_transport_len;
}

/* One accepted IPv4 packet: fake DNS, routing, listener setup, then the stack. */
static void processV4(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    struct ip_hdr *iphdr = (struct ip_hdr *) sbufGetMutablePtr(buf);
    ip_addr_t      dest_ip;

    if (! ptcValidateIpv4Packet(buf, iphdr))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (UNLIKELY(! deviceFragClaimPacketMatches(buf)))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    const uint16_t total_len = lwip_ntohs(IPH_LEN(iphdr));
    if (UNLIKELY(sbufGetLength(buf) != total_len))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (IPH_PROTO(iphdr) != IP_PROTO_TCP && IPH_PROTO(iphdr) != IP_PROTO_UDP)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    ipAddrCopyFromIp4(dest_ip, iphdr->dest);

    /*
     * Fake DNS answers from a single packet, so it can only be offered whole
     * datagrams.
     *
     * A fragment must never reach it. Fragment zero's UDP length describes the
     * entire datagram and therefore exceeds that fragment's IPv4 total length,
     * which the parser reads as malformed - and it reports the packet consumed,
     * so reassembly could never complete. A fragment at a nonzero offset has no
     * UDP header at all, and its first payload bytes could be misread as one.
     */
    const bool is_fragment = (lwip_ntohs(IPH_OFFSET(iphdr)) & (IP_MF | IP_OFFMASK)) != 0;

    if (IPH_PROTO(iphdr) == IP_PROTO_UDP && ! is_fragment &&
        ptcPacketHasTransportHeader(buf, iphdr, sizeof(struct udp_hdr)))
    {
        struct udp_hdr *udphdr = (struct udp_hdr *) ((uint8_t *) iphdr + IPH_HL_BYTES(iphdr));

        const ptc_fake_dns_result_t dns_result = ptcFakeDnsHandleIpv4UdpPacket(t, l, buf, iphdr, udphdr);
        if (dns_result.handled)
        {
            /*
             * Published here rather than returned for emission after the unlock:
             * the reply has to leave through the worker netif so lwIP fragments
             * it at the configured MTU. That output callback only queues, so it
             * is legal while the core lock is held.
             */
            if (dns_result.response != NULL)
            {
                discard ptcFakeDnsPublishResponseLocked(
                    t, l, dns_result.response, &dns_result.source, &dns_result.destination);
            }
            return;
        }
    }

    ptc_tstate_t *ts = tunnelGetState(t);
    if (UNLIKELY(ptcFakeDnsShouldDropFragment(&ts->fake_dns, &iphdr->dest, IPH_PROTO(iphdr), is_fragment)))
    {
        /*
         * Fragmented UDP addressed to the fake-DNS endpoint. Answering it would
         * need the query to come from a real UDP PCB rather than this pre-lwIP
         * parser, so the limitation is reported rather than hidden behind a
         * fragment that quietly disappears.
         *
         * The destination port cannot be checked here: only fragment zero carries
         * a UDP header, and reading one out of a nonzero fragment's payload bytes
         * would be guessing. The whole fake-DNS address is therefore reserved for
         * fragmented UDP, which is why the protocol test above matters - without
         * it this also swallowed fragmented TCP to the same address, traffic that
         * has nothing to do with DNS.
         */
        if (atomicLogRateLimiterShouldLog(&fake_dns_fragment_log, kPtcRxPoolExhaustionLogIntervalMs))
        {
            LOGW("PacketsToConnection: dropping a fragmented UDP packet addressed to the fake-DNS endpoint; "
                 "fragmented UDP to that address is not supported");
        }
        deviceFragClaimResolveBuffer(buf, kDeviceFragSettlementNoResidue);
        lineReuseBuffer(l, buf);
        return;
    }

    interface_route_context_t *route_ctx = ptcFindOrCreateRouteContextV4(t, lineGetWID(l), &dest_ip.u_addr.ip4);
    if (route_ctx == NULL)
    {
        LOGW("PacketsToConnection: failed to create virtual netif for destination");
        lineReuseBuffer(l, buf);
        return;
    }

    /*
     * From here on there is a netif to name, so a refusal can purge the exact
     * reassembly key instead of leaving the device to quarantine the identity.
     * Everything refused above this point has no route, and therefore no netif
     * an earlier fragment of this datagram could have entered through.
     */
    ptc_fragment_key_t fragment_key;
    const bool         tracked_fragment = ptcReadFragmentKey(buf, &fragment_key);

    switch (IPH_PROTO(iphdr))
    {
    case IP_PROTO_TCP:
        if (ptcEnsureTcpListener(route_ctx, t, &dest_ip, 0) != ERR_OK)
        {
            LOGW("PacketsToConnection: failed to create pretend TCP gateway");
            if (tracked_fragment)
            {
                ptcReportFragmentRefusalLocked(&fragment_key, &route_ctx->netif, buf);
            }
            lineReuseBuffer(l, buf);
            return;
        }
        break;

    case IP_PROTO_UDP:
        if (ptcEnsureUdpListener(route_ctx, t, &dest_ip, 0) != ERR_OK)
        {
            LOGW("PacketsToConnection: failed to create pretend UDP gateway");
            if (tracked_fragment)
            {
                ptcReportFragmentRefusalLocked(&fragment_key, &route_ctx->netif, buf);
            }
            lineReuseBuffer(l, buf);
            return;
        }
        break;

    default:
        if (tracked_fragment)
        {
            ptcReportFragmentRefusalLocked(&fragment_key, &route_ctx->netif, buf);
        }
        lineReuseBuffer(l, buf);
        return;
    }

    ptcSubmitPacketToStack(buf, &route_ctx->netif);
}

void ptcTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ptc_tstate_t *state                = tunnelGetState(t);
    const bool    recalculate_checksum = packettunnelTakeChecksumRequest(l);

    if (UNLIKELY(atomicLoadRelaxed(&state->stopping)))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (UNLIKELY(sbufGetLength(buf) < 1))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    const uint8_t version = ((const uint8_t *) sbufGetRawPtr(buf))[0] >> 4U;

    if (version == 4)
    {
        /* Classify from bytes first; no typed packet access is legal before this copy. */
        if (UNLIKELY(ptcPacketNeedsAlignedCopy(buf)))
        {
            sbuf_t *aligned = ptcAcquireAlignedCopy(lineGetBufferPool(l), buf);

            lineReuseBuffer(l, buf);
            if (UNLIKELY(aligned == NULL))
            {
                return;
            }
            buf = aligned;
        }

        if (UNLIKELY(! packettunnelFinalizeChecksumRequest(
                recalculate_checksum, sbufGetMutablePtr(buf), sbufGetLength(buf))))
        {
            lineReuseBuffer(l, buf);
            return;
        }

        LOCK_TCPIP_CORE();

        /*
         * Stop may have won the core lock after our optimistic check and
         * removed every route. Recheck under the same lock that serializes
         * route creation so cleanup is a stable barrier.
         */
        if (UNLIKELY(atomicLoadRelaxed(&state->stopping)))
        {
            UNLOCK_TCPIP_CORE();
            lineReuseBuffer(l, buf);
            return;
        }

        processV4(t, l, buf);
        UNLOCK_TCPIP_CORE();
        ptcDrainTerminalLinesOnCurrentWorker(t, lineGetWID(l));
        return;
    }

    lineReuseBuffer(l, buf);
}
