#include "trick.h"

#include "loggers/network_logger.h"

api_result_t tlsclientTunnelApi(tunnel_t *instance, sbuf_t *message);

enum
{
    kSmuggleSniWarmupPackets  = 2,
    kSmuggleSniCapturePackets = 1,
    kSmuggleSniDelayWindowMs  = 50000,
    kSmuggleSniIdleTimeoutMs  = 20U * 60U * 1000U
};

typedef struct smugglesnitrick_tcp_packet_info_s
{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint32_t payload_offset;
    uint8_t  tcp_flags;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t ip_total_len;
    uint16_t tcp_payload_len;
} smugglesnitrick_tcp_packet_info_t;

typedef enum smugglesnitrick_action_e
{
    kSmuggleSniActionPassNormal = 0,
    kSmuggleSniActionDelayNormal,
    kSmuggleSniActionPassReal
} smugglesnitrick_action_e;

typedef struct smugglesnitrick_completion_s
{
    bool                                 ready;
    uint32_t                             captured_payload_sum;
    ipmanipulator_smuggle_saved_packet_t saved_packets[kIpManipulatorSmuggleSavedPacketsCount];
} smugglesnitrick_completion_t;

static void smugglesnitrickResetSavedPacket(ipmanipulator_smuggle_saved_packet_t *saved_packet)
{
    memoryZero(saved_packet, sizeof(*saved_packet));
}

static void smugglesnitrickDestroySavedPacket(ipmanipulator_smuggle_saved_packet_t *saved_packet)
{
    if (saved_packet->packet != NULL)
    {
        sbufDestroy(saved_packet->packet);
    }

    smugglesnitrickResetSavedPacket(saved_packet);
}

static void smugglesnitrickDestroyFlow(ipmanipulator_smuggle_flow_t *flow)
{
    for (uint32_t i = 0; i < kIpManipulatorSmuggleSavedPacketsCount; ++i)
    {
        smugglesnitrickDestroySavedPacket(&flow->saved_packets[i]);
    }

    memoryZero(flow, sizeof(*flow));
}

static void smugglesnitrickMoveCompletionOut(smugglesnitrick_completion_t *completion,
                                             ipmanipulator_smuggle_flow_t *flow)
{
    if (completion == NULL || flow == NULL)
    {
        return;
    }

    completion->ready                = true;
    completion->captured_payload_sum = flow->captured_payload_sum;

    for (uint32_t i = 0; i < kIpManipulatorSmuggleSavedPacketsCount; ++i)
    {
        completion->saved_packets[i] = flow->saved_packets[i];
        smugglesnitrickResetSavedPacket(&flow->saved_packets[i]);
    }

    flow->capture_packets_seen = 0;
    flow->captured_payload_sum = 0;
}

static void smugglesnitrickDestroyCompletion(smugglesnitrick_completion_t *completion)
{
    if (completion == NULL)
    {
        return;
    }

    for (uint32_t i = 0; i < kIpManipulatorSmuggleSavedPacketsCount; ++i)
    {
        smugglesnitrickDestroySavedPacket(&completion->saved_packets[i]);
    }

    memoryZero(completion, sizeof(*completion));
}

static bool smugglesnitrickParseTcpPacketInfo(const uint8_t *packet, uint32_t packet_length,
                                              smugglesnitrick_tcp_packet_info_t *info)
{
    if (packet_length < sizeof(struct ip_hdr))
    {
        return false;
    }

    const struct ip_hdr *ipheader = (const struct ip_hdr *) packet;
    if (IPH_V(ipheader) != 4 || IPH_PROTO(ipheader) != IPPROTO_TCP)
    {
        return false;
    }

    uint8_t ip_hdr_len_words = IPH_HL(ipheader);
    if (ip_hdr_len_words < 5 || ip_hdr_len_words > 15)
    {
        return false;
    }

    uint16_t ip_header_len = (uint16_t) (ip_hdr_len_words * 4);
    if (packet_length < ip_header_len + sizeof(struct tcp_hdr))
    {
        return false;
    }

    uint16_t ip_total_len = lwip_ntohs(IPH_LEN(ipheader));
    if (ip_total_len < ip_header_len + sizeof(struct tcp_hdr) || packet_length < ip_total_len)
    {
        return false;
    }

    uint16_t off_f = lwip_ntohs(IPH_OFFSET(ipheader));
    if ((off_f & (IP_MF | IP_OFFMASK)) != 0)
    {
        return false;
    }

    const struct tcp_hdr *tcp_header        = (const struct tcp_hdr *) (packet + ip_header_len);
    uint8_t               tcp_hdr_len_words = TCPH_HDRLEN(tcp_header);
    if (tcp_hdr_len_words < 5 || tcp_hdr_len_words > 15)
    {
        return false;
    }

    uint16_t tcp_header_len = (uint16_t) (tcp_hdr_len_words * 4);
    uint16_t headers_len    = (uint16_t) (ip_header_len + tcp_header_len);
    if (ip_total_len < headers_len)
    {
        return false;
    }

    *info = (smugglesnitrick_tcp_packet_info_t) {
        .src_addr        = ipheader->src.addr,
        .dst_addr        = ipheader->dest.addr,
        .payload_offset  = headers_len,
        .tcp_flags       = TCPH_FLAGS(tcp_header),
        .src_port        = lwip_ntohs(tcp_header->src),
        .dst_port        = lwip_ntohs(tcp_header->dest),
        .ip_total_len    = ip_total_len,
        .tcp_payload_len = (uint16_t) (ip_total_len - headers_len),
    };

    return true;
}

static bool smugglesnitrickIsPureSyn(const smugglesnitrick_tcp_packet_info_t *info)
{
    return info->tcp_flags == TCP_SYN;
}

static bool smugglesnitrickHasFinOrRst(const smugglesnitrick_tcp_packet_info_t *info)
{
    return (info->tcp_flags & (TCP_FIN | TCP_RST)) != 0;
}

static bool smugglesnitrickFlowMatches(const ipmanipulator_smuggle_flow_t      *flow,
                                       const smugglesnitrick_tcp_packet_info_t *info)
{
    return flow->active && flow->src_addr == info->src_addr && flow->dst_addr == info->dst_addr &&
           flow->src_port == info->src_port && flow->dst_port == info->dst_port;
}

static bool smugglesnitrickFlowMatchesReverse(const ipmanipulator_smuggle_flow_t      *flow,
                                              const smugglesnitrick_tcp_packet_info_t *info)
{
    return flow->active && flow->src_addr == info->dst_addr && flow->dst_addr == info->src_addr &&
           flow->src_port == info->dst_port && flow->dst_port == info->src_port;
}

static sbuf_t *smugglesnitrickDuplicateStandalonePacket(const sbuf_t *source)
{
    uint32_t packet_len = sbufGetLength(source);
    sbuf_t  *copy       = sbufCreateWithPadding(packet_len, sbufGetLeftPadding(source));

    if (copy == NULL)
    {
        return NULL;
    }

    sbufSetLength(copy, packet_len);
    memoryCopyLarge(sbufGetMutablePtr(copy), sbufGetRawPtr(source), packet_len);
    return copy;
}

static void smugglesnitrickCleanupIdleFlowsLocked(ipmanipulator_tstate_t *state, uint64_t now_ms)
{
    for (uint32_t i = 0; i < state->smuggle_flows_capacity; ++i)
    {
        ipmanipulator_smuggle_flow_t *flow = &state->smuggle_flows[i];

        if (! flow->active)
        {
            continue;
        }

        if (now_ms - flow->last_activity_ms < kSmuggleSniIdleTimeoutMs)
        {
            continue;
        }

        smugglesnitrickDestroyFlow(flow);
    }
}

static ipmanipulator_smuggle_flow_t *smugglesnitrickFindFlowLocked(ipmanipulator_tstate_t                  *state,
                                                                   const smugglesnitrick_tcp_packet_info_t *info)
{
    for (uint32_t i = 0; i < state->smuggle_flows_capacity; ++i)
    {
        if (smugglesnitrickFlowMatches(&state->smuggle_flows[i], info))
        {
            return &state->smuggle_flows[i];
        }
    }

    return NULL;
}

static ipmanipulator_smuggle_flow_t *smugglesnitrickFindReverseFlowLocked(ipmanipulator_tstate_t *state,
                                                                          const smugglesnitrick_tcp_packet_info_t *info)
{
    for (uint32_t i = 0; i < state->smuggle_flows_capacity; ++i)
    {
        if (smugglesnitrickFlowMatchesReverse(&state->smuggle_flows[i], info))
        {
            return &state->smuggle_flows[i];
        }
    }

    return NULL;
}

static ipmanipulator_smuggle_flow_t *smugglesnitrickCreateFlowLocked(ipmanipulator_tstate_t                  *state,
                                                                     const smugglesnitrick_tcp_packet_info_t *info,
                                                                     uint64_t                                 now_ms)
{
    for (uint32_t i = 0; i < state->smuggle_flows_capacity; ++i)
    {
        ipmanipulator_smuggle_flow_t *flow = &state->smuggle_flows[i];

        if (flow->active)
        {
            continue;
        }

        *flow = (ipmanipulator_smuggle_flow_t) {
            .created_ms       = now_ms,
            .last_activity_ms = now_ms,
            .src_addr         = info->src_addr,
            .dst_addr         = info->dst_addr,
            .src_port         = info->src_port,
            .dst_port         = info->dst_port,
            .phase            = kIpManipulatorSmuggleFlowPhaseWarmup,
            .active           = true,
        };

        return flow;
    }

    uint32_t                      old_capacity = state->smuggle_flows_capacity;
    uint32_t                      new_capacity = max(kIpManipulatorSmuggleInitialFlows, old_capacity * 2U);
    ipmanipulator_smuggle_flow_t *grown =
        memoryReAllocate(state->smuggle_flows, sizeof(*state->smuggle_flows) * new_capacity);

    if (grown == NULL)
    {
        return NULL;
    }

    memoryZero(grown + old_capacity, sizeof(*grown) * (new_capacity - old_capacity));
    state->smuggle_flows          = grown;
    state->smuggle_flows_capacity = new_capacity;

    ipmanipulator_smuggle_flow_t *flow = &state->smuggle_flows[old_capacity];
    *flow                              = (ipmanipulator_smuggle_flow_t) {
                                     .created_ms       = now_ms,
                                     .last_activity_ms = now_ms,
                                     .src_addr         = info->src_addr,
                                     .dst_addr         = info->dst_addr,
                                     .src_port         = info->src_port,
                                     .dst_port         = info->dst_port,
                                     .phase            = kIpManipulatorSmuggleFlowPhaseWarmup,
                                     .active           = true,
    };

    return flow;
}

static void smugglesnitrickSendNormalNow(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard portghosttrickApply(t, l, &buf);
    if (buf == NULL)
    {
        return;
    }

    lineSetRecalculateChecksum(l, true);
    tunnelNextUpStreamPayload(t, l, buf);
}

static void smugglesnitrickSendRealNow(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    lineSetRecalculateChecksum(l, true);
    tunnelUpStreamPayload(state->trick_real_sni_upstream_tunnel, l, buf);
}

static void smugglesnitrickRunDelayedNormal(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;

    tunnel_t *t   = arg1;
    line_t   *l   = arg2;
    sbuf_t   *buf = arg3;

    if (lineIsAlive(l))
    {
        smugglesnitrickSendNormalNow(t, l, buf);
    }
    else
    {
        lineReuseBuffer(l, buf);
    }

    lineUnlock(l);
}

static void smugglesnitrickCleanupDelayedBuffer(line_t *l, sbuf_t *buf)
{
    if (buf == NULL)
    {
        return;
    }

    if (getWID() == lineGetWID(l))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    sbufDestroy(buf);
}

static void smugglesnitrickCleanupDelayedNormal(void *arg1, void *arg2, void *arg3)
{
    discard arg1;

    line_t *l   = arg2;
    sbuf_t *buf = arg3;

    smugglesnitrickCleanupDelayedBuffer(l, buf);
    lineUnlock(l);
}

static void smugglesnitrickScheduleNormalSend(tunnel_t *t, line_t *l, sbuf_t *buf, uint32_t delay_ms)
{
    if (delay_ms == 0 && getWID() == lineGetWID(l))
    {
        smugglesnitrickSendNormalNow(t, l, buf);
        return;
    }

    lineLock(l);
    sendWorkerMessageTimedWithCleanup(lineGetWID(l),
                                      (WorkerMessageCallback) smugglesnitrickRunDelayedNormal,
                                      smugglesnitrickCleanupDelayedNormal,
                                      delay_ms,
                                      t,
                                      l,
                                      buf);
}

static sbuf_t *smugglesnitrickAllocateRequestBuffer(uint32_t len)
{
    buffer_pool_t *pool = getWorkerBufferPool(getWID());

    if (len <= bufferpoolGetSmallBufferSize(pool))
    {
        return bufferpoolGetSmallBuffer(pool);
    }

    if (len <= bufferpoolGetLargeBufferSize(pool))
    {
        return bufferpoolGetLargeBuffer(pool);
    }

    return sbufCreate(len);
}

static sbuf_t *smugglesnitrickGenerateTlsClientHello(tunnel_t *t)
{
    static const char kGenerateTlsHelloPrefix[] = "generateTlsHello:";

    ipmanipulator_tstate_t *state = tunnelGetState(t);
    uint32_t request_len = (uint32_t) (sizeof(kGenerateTlsHelloPrefix) - 1) + state->trick_smuggle_sni_value_len;
    sbuf_t  *request_buf = smugglesnitrickAllocateRequestBuffer(request_len);

    if (request_buf == NULL)
    {
        return NULL;
    }

    sbufSetLength(request_buf, request_len);
    memoryCopy(sbufGetMutablePtr(request_buf), kGenerateTlsHelloPrefix, sizeof(kGenerateTlsHelloPrefix) - 1);
    memoryCopy(sbufGetMutablePtr(request_buf) + (sizeof(kGenerateTlsHelloPrefix) - 1),
               state->trick_smuggle_sni_value,
               state->trick_smuggle_sni_value_len);

    api_result_t result = tlsclientTunnelApi(state->trick_real_sni_tls_client_tunnel, request_buf);

    if (result.result_code != kApiResultOk || result.buffer == NULL)
    {
        if (result.buffer != NULL)
        {
            reuseBuffer(result.buffer);
        }

        return NULL;
    }

    return result.buffer;
}

static bool smugglesnitrickRewriteSavedPacketPayload(ipmanipulator_smuggle_saved_packet_t *saved_packet,
                                                     const uint8_t *payload, uint32_t payload_len)
{
    smugglesnitrick_tcp_packet_info_t info = {0};

    if (saved_packet == NULL || saved_packet->packet == NULL)
    {
        return false;
    }

    if (! smugglesnitrickParseTcpPacketInfo(
            (const uint8_t *) sbufGetRawPtr(saved_packet->packet), sbufGetLength(saved_packet->packet), &info))
    {
        return false;
    }

    if ((uint32_t) saved_packet->payload_len != payload_len || (uint32_t) info.tcp_payload_len != payload_len ||
        info.payload_offset + payload_len > sbufGetLength(saved_packet->packet))
    {
        return false;
    }

    memoryCopyLarge(sbufGetMutablePtr(saved_packet->packet) + info.payload_offset, payload, payload_len);
    return true;
}

static bool smugglesnitrickBuildFakePackets(tunnel_t *t, smugglesnitrick_completion_t *completion)
{
    if (completion == NULL || ! completion->ready)
    {
        return false;
    }

    if (completion->captured_payload_sum == 0)
    {
        return false;
    }

    for (;;)
    {
        sbuf_t *tls_hello = smugglesnitrickGenerateTlsClientHello(t);

        if (tls_hello == NULL)
        {
            return false;
        }

        if (sbufGetLength(tls_hello) != completion->captured_payload_sum)
        {
            reuseBuffer(tls_hello);
            continue;
        }

        const uint8_t *hello_payload = (const uint8_t *) sbufGetRawPtr(tls_hello);
        uint32_t       offset        = 0;
        bool           rewrite_ok    = true;

        for (uint32_t i = 0; i < kIpManipulatorSmuggleSavedPacketsCount; ++i)
        {
            uint32_t this_payload_len = completion->saved_packets[i].payload_len;

            rewrite_ok &= smugglesnitrickRewriteSavedPacketPayload(
                &completion->saved_packets[i], hello_payload + offset, this_payload_len);
            offset += this_payload_len;
        }

        reuseBuffer(tls_hello);
        return rewrite_ok;
    }
}

void smugglesnitrickDestroyState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (state->smuggle_flows == NULL)
    {
        return;
    }

    mutexLock(&state->smuggle_flows_mutex);

    for (uint32_t i = 0; i < state->smuggle_flows_capacity; ++i)
    {
        smugglesnitrickDestroyFlow(&state->smuggle_flows[i]);
    }

    mutexUnlock(&state->smuggle_flows_mutex);
    mutexDestroy(&state->smuggle_flows_mutex);

    memoryFree(state->smuggle_flows);
    state->smuggle_flows          = NULL;
    state->smuggle_flows_capacity = 0;
}

void smugglesnitrickLogDownStreamServerHello(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard l;

    smugglesnitrick_tcp_packet_info_t info   = {0};
    const uint8_t                    *packet = (const uint8_t *) sbufGetRawPtr(buf);

    if (! smugglesnitrickParseTcpPacketInfo(packet, sbufGetLength(buf), &info))
    {
        return;
    }

    if (smugglesnitrickHasFinOrRst(&info))
    {
        ipmanipulator_tstate_t *state = tunnelGetState(t);

        mutexLock(&state->smuggle_flows_mutex);

        ipmanipulator_smuggle_flow_t *flow = smugglesnitrickFindReverseFlowLocked(state, &info);
        if (flow != NULL)
        {
            smugglesnitrickDestroyFlow(flow);
        }

        mutexUnlock(&state->smuggle_flows_mutex);
    }

    if (info.tcp_payload_len < 9)
    {
        return;
    }

    const uint8_t *tls = packet + info.payload_offset;
    if (tls[0] != 0x16 || tls[1] != 0x03 || tls[5] != 0x02)
    {
        return;
    }

    ipmanipulator_tstate_t *state = tunnelGetState(t);

    LOGD("IpManipulator: smuggle-sni saw downstream TLS ServerHello for fake-sni=\"%s\" on %u:%u -> %u:%u",
         state->trick_smuggle_sni_value,
         info.src_addr,
         info.src_port,
         info.dst_addr,
         info.dst_port);
}

bool smugglesnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t           *state      = tunnelGetState(t);
    smugglesnitrick_tcp_packet_info_t info       = {0};
    smugglesnitrick_completion_t      completion = {0};
    smugglesnitrick_action_e          action     = kSmuggleSniActionPassNormal;
    uint64_t                          now_ms     = getTickMS();

    if (! smugglesnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return false;
    }

    mutexLock(&state->smuggle_flows_mutex);
    smugglesnitrickCleanupIdleFlowsLocked(state, now_ms);

    ipmanipulator_smuggle_flow_t *flow = smugglesnitrickFindFlowLocked(state, &info);
    if (flow == NULL)
    {
        if (! smugglesnitrickIsPureSyn(&info))
        {
            mutexUnlock(&state->smuggle_flows_mutex);
            return false;
        }

        flow = smugglesnitrickCreateFlowLocked(state, &info, now_ms);
    }

    if (flow == NULL)
    {
        mutexUnlock(&state->smuggle_flows_mutex);
        LOGW("IpManipulator: smuggle-sni failed to allocate a shared connection record");
        return false;
    }

    flow->last_activity_ms = now_ms;

    if (smugglesnitrickHasFinOrRst(&info))
    {
        smugglesnitrickDestroyFlow(flow);
        mutexUnlock(&state->smuggle_flows_mutex);
        return false;
    }

    switch (flow->phase)
    {
    case kIpManipulatorSmuggleFlowPhaseWarmup:
        flow->warmup_packets_seen += 1;
        if (flow->warmup_packets_seen >= kSmuggleSniWarmupPackets)
        {
            flow->phase = kIpManipulatorSmuggleFlowPhaseCapture;
        }
        action = kSmuggleSniActionPassNormal;
        break;

    case kIpManipulatorSmuggleFlowPhaseCapture: {
        uint32_t slot_index = flow->capture_packets_seen;
        sbuf_t  *copy       = smugglesnitrickDuplicateStandalonePacket(buf);

        if (copy == NULL || slot_index >= kIpManipulatorSmuggleSavedPacketsCount)
        {
            if (copy != NULL)
            {
                sbufDestroy(copy);
            }

            flow->phase                = kIpManipulatorSmuggleFlowPhasePassthrough;
            flow->capture_packets_seen = 0;
            flow->captured_payload_sum = 0;

            for (uint32_t i = 0; i < kIpManipulatorSmuggleSavedPacketsCount; ++i)
            {
                smugglesnitrickDestroySavedPacket(&flow->saved_packets[i]);
            }

            action = kSmuggleSniActionPassReal;
            break;
        }

        flow->saved_packets[slot_index] =
            (ipmanipulator_smuggle_saved_packet_t) {.line = l, .packet = copy, .payload_len = info.tcp_payload_len};
        flow->capture_packets_seen += 1;
        flow->captured_payload_sum += info.tcp_payload_len;
        action = kSmuggleSniActionPassReal;

        if (flow->capture_packets_seen >= kSmuggleSniCapturePackets)
        {
            flow->phase                 = kIpManipulatorSmuggleFlowPhasePassthrough;
            flow->delay_window_until_ms = now_ms + kSmuggleSniDelayWindowMs;
            smugglesnitrickMoveCompletionOut(&completion, flow);
        }
        break;
    }

    case kIpManipulatorSmuggleFlowPhasePassthrough:
        action = (now_ms < flow->delay_window_until_ms) ? kSmuggleSniActionDelayNormal : kSmuggleSniActionPassNormal;
        break;
    }

    mutexUnlock(&state->smuggle_flows_mutex);

    switch (action)
    {
    case kSmuggleSniActionDelayNormal:
        smugglesnitrickScheduleNormalSend(t, l, buf, state->trick_smuggle_sni_delay_ms);
        break;

    case kSmuggleSniActionPassReal:
        smugglesnitrickSendRealNow(t, l, buf);
        break;

    case kSmuggleSniActionPassNormal:
    default:
        smugglesnitrickSendNormalNow(t, l, buf);
        break;
    }

    if (completion.ready)
    {
        if (smugglesnitrickBuildFakePackets(t, &completion))
        {
            LOGD("IpManipulator: smuggle-sni sent the real packets immediately to \"%s\" and scheduled the fake SNI "
                 "\"%s\" packets after %u ms",
                 state->trick_real_sni_upstream_node->name,
                 state->trick_smuggle_sni_value,
                 state->trick_smuggle_sni_delay_ms);

            for (uint32_t i = 0; i < kIpManipulatorSmuggleSavedPacketsCount; ++i)
            {
                if (completion.saved_packets[i].line != NULL && completion.saved_packets[i].packet != NULL)
                {
                    LOGD("scheduling size %u bytes normal send for captured packet with payload_len=%u",
                         sbufGetLength(completion.saved_packets[i].packet),
                         completion.saved_packets[i].payload_len);
                    smugglesnitrickScheduleNormalSend(t,
                                                      completion.saved_packets[i].line,
                                                      completion.saved_packets[i].packet,
                                                      state->trick_smuggle_sni_delay_ms + (2 * i));
                    smugglesnitrickResetSavedPacket(&completion.saved_packets[i]);
                }
            }
        }

        smugglesnitrickDestroyCompletion(&completion);
    }

    return true;
}
