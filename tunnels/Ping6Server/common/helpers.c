#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kPing6ServerDropLogIntervalMs = 5U * 1000U,
};

static void ping6serverValidatePacketLine(tunnel_t *t, line_t *l)
{
    ping6server_tstate_t *state = tunnelGetState(t);

    if (UNLIKELY(! lineIsAlive(l) || ! lineIsOnCurrentWorker(l) ||
                 ! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l) || state->tracker == NULL || ! state->started))
    {
        LOGF("Ping6Server: invalid worker packet-line callback");
        abortProgramNow(1);
    }
}

static void ping6serverDrop(tunnel_t *t, line_t *l, sbuf_t *buf, const char *direction, const char *reason)
{
    ping6server_tstate_t *state = tunnelGetState(t);
    if (atomicLogRateLimiterShouldLog(&state->drop_log_limiter, kPing6ServerDropLogIntervalMs))
    {
        LOGE("Ping6Server: dropping %s packet: %s (packet-bytes=%zu, max-inner-bytes=%u, overhead-bytes=%u, "
             "max-carrier-bytes=%u, headroom-bytes=%zu, required-headroom-bytes=%u)",
             direction,
             reason,
             sbufGetLength(buf),
             (unsigned int) kPing6WireMaxInnerPacketLength,
             (unsigned int) kPing6WireEncapsulationOverhead,
             (unsigned int) kMaxAllowedPacketLength,
             sbufGetHeadroom(buf),
             (unsigned int) kPing6WireEncapsulationOverhead);
    }
    lineReuseBuffer(l, buf);
}

static const char *ping6serverConsumeInnerChecksum(sbuf_t *buf)
{
    const bool  requested = packettunnelTakeChecksumRequest(buf);
    const char *error     = pingwireIpv4PacketError(sbufGetRawPtr(buf), sbufGetLength(buf));
    if (error != NULL)
    {
        return error;
    }
    if (requested && ! calcFullPacketChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf)))
    {
        return "requested IPv4/transport checksum repair failed";
    }
    return NULL;
}

static const char *ping6serverConsumeCarrierChecksum(ping6server_tstate_t *state, sbuf_t *buf)
{
    const bool         requested = packettunnelTakeChecksumRequest(buf);
    ipv4_packet_view_t outer     = {0};
    const char        *error     = pingwireIpv4PacketErrorWithView(sbufGetRawPtr(buf), sbufGetLength(buf), &outer);
    if (error != NULL)
    {
        return error;
    }
    if (! requested)
    {
        return NULL;
    }

    if (outer.source_address != state->wire.peer_ipv4 || outer.destination_address != state->wire.local_ipv4 ||
        outer.protocol != kPing6WireProtocol)
    {
        sbufSetRecalculateChecksum(buf, true);
        return NULL;
    }
    if (! ping6wireRecalculateCarrierChecksums(buf, &state->wire.peer_ipv6, &state->wire.local_ipv6))
    {
        /* Not a repairable carrier shape: settle the outer header so the parser can name the exact reason. */
        discard calcIpv4HeaderChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf));
    }
    return NULL;
}

void ping6serverHandleDownstreamPacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ping6server_tstate_t *state = tunnelGetState(t);
    ping6serverValidatePacketLine(t, l);

    const char *input_error = ping6serverConsumeInnerChecksum(buf);
    if (input_error != NULL)
    {
        ping6serverDrop(t, l, buf, "outgoing", input_error);
        return;
    }

    if (sbufGetLength(buf) > kPing6WireMaxInnerPacketLength)
    {
        ping6serverDrop(t, l, buf, "outgoing", "IPv4 packet exceeds maximum inner size");
        return;
    }
    if (sbufGetHeadroom(buf) < kPing6WireEncapsulationOverhead)
    {
        ping6serverDrop(t, l, buf, "outgoing", "insufficient left headroom to prepend IPv4/ICMPv6 headers");
        return;
    }

    const uint16_t sequence = (uint16_t) atomicAdd(&state->next_sequence, 1U);
    if (UNLIKELY(! ping6wireBuildEchoRequest(buf, &state->wire, sequence)))
    {
        LOGF("Ping6Server: Echo Request build failed after successful preflight");
        abortProgramNow(1);
    }

    const uint8_t *payload        = sbufGetRawPtr(buf) + kPing6WireEncapsulationOverhead;
    const uint16_t payload_length = (uint16_t) (sbufGetLength(buf) - kPing6WireEncapsulationOverhead);
    if (! pingwireOutstandingRecord(state->tracker,
                                    state->digest_key,
                                    state->wire.identifier,
                                    sequence,
                                    state->wire.peer_ipv4,
                                    state->wire.local_ipv4,
                                    payload,
                                    payload_length))
    {
        ping6serverDrop(t, l, buf, "outgoing", "failed to hash/register the outgoing Echo Request");
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}

void ping6serverHandleUpstreamPacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ping6server_tstate_t *state = tunnelGetState(t);
    ping6serverValidatePacketLine(t, l);

    const char *input_error = ping6serverConsumeCarrierChecksum(state, buf);
    if (input_error != NULL)
    {
        ping6serverDrop(t, l, buf, "incoming", input_error);
        return;
    }
    if (sbufGetRecalculateChecksum(buf))
    {
        /* Only unrelated traffic keeps its pending repair; its possibly stale checksums are not ours to judge. */
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    ping_wire_envelope_t           envelope = {0};
    const ping_wire_inbound_kind_t kind =
        ping6wireParseInbound(sbufGetRawPtr(buf), sbufGetLength(buf), &state->wire, &envelope);
    if (kind == kPingWireInboundUnrelated)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }
    if (kind == kPingWireInboundMalformed || kind == kPingWireInboundInvalidCarrier)
    {
        assert(envelope.error_reason != NULL);
        ping6serverDrop(t, l, buf, "incoming", envelope.error_reason);
        return;
    }

    if (kind == kPingWireInboundEchoReply)
    {
        if (pingwireOutstandingConsumeForType(state->tracker, state->digest_key, &envelope, kPing6WireEchoReply))
        {
            lineReuseBuffer(l, buf);
            return;
        }

        /* A valid but unmatched reply is unrelated IP traffic, not tunnel data. */
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    assert(kind == kPingWireInboundEchoRequest);
    const ping_wire_replay_result_t replay =
        pingwireReplayMarkForType(state->tracker, state->digest_key, &envelope, kPing6WireEchoRequest);
    if (replay == kPingWireReplayError)
    {
        ping6serverDrop(
            t, l, buf, "incoming", "failed to hash/record the incoming Echo Request for duplicate detection");
        return;
    }

    if (state->send_replies)
    {
        /* The validated request's exact clone satisfies the reply builder and preserves every ICMPv6 byte. */
        sbuf_t    *reply       = sbufDuplicateByPool(lineGetBufferPool(l), buf);
        const bool reply_built = ping6wireBuildEchoReply(
            reply,
            &state->wire,
            &envelope,
            pingwireReplyIdGeneratorNext(&state->reply_ids, wloopNowMonotonicMS(getWorkerLoop(lineGetWID(l)))));
        assert(reply_built);
        discard reply_built;

        lineRef(l);
        tunnelPrevDownStreamPayload(t, l, reply);
        if (UNLIKELY(! lineIsAlive(l)))
        {
            LOGF("Ping6Server: worker packet line died during generated Echo Reply callback");
            abortProgramNow(1);
        }
        lineUnref(l);
    }

    if (replay == kPingWireReplayDuplicate)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    /* Only the reply clone crossed a callback; the original request and its envelope are unchanged. */
    const bool stripped = ping6wireStripEchoRequest(buf, &envelope);
    assert(stripped);
    discard stripped;

    sbufSetRecalculateChecksum(buf, false);
    /* Decoding retains receive placement; stateful consumers establish affinity. */
    tunnelNextUpStreamPayload(t, l, buf);
}
