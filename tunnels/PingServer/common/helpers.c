#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kPingServerDropLogIntervalMs = 5U * 1000U,
};

static void pingserverValidatePacketLine(tunnel_t *t, line_t *l)
{
    pingserver_tstate_t *state = tunnelGetState(t);

    if (UNLIKELY(! lineIsAlive(l) || ! lineIsOnCurrentWorker(l) ||
                 ! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l) || state->tracker == NULL || ! state->started))
    {
        LOGF("PingServer: invalid worker packet-line callback");
        abortProgramNow(1);
    }
}

static void pingserverDrop(tunnel_t *t, line_t *l, sbuf_t *buf, const char *direction, const char *reason)
{
    pingserver_tstate_t *state = tunnelGetState(t);
    if (atomicLogRateLimiterShouldLog(&state->drop_log_limiter, kPingServerDropLogIntervalMs))
    {
        LOGE("PingServer: dropping %s packet: %s (packet-bytes=%zu, max-inner-bytes=%u, overhead-bytes=%u, "
             "max-carrier-bytes=%u, headroom-bytes=%zu, required-headroom-bytes=%u)",
             direction,
             reason,
             sbufGetLength(buf),
             (unsigned int) kPingWireMaxInnerPacketLength,
             (unsigned int) kPingWireEncapsulationOverhead,
             (unsigned int) kMaxAllowedPacketLength,
             sbufGetHeadroom(buf),
             (unsigned int) kPingWireEncapsulationOverhead);
    }
    lineReuseBuffer(l, buf);
}

static const char *pingserverConsumeCarrierChecksum(pingserver_tstate_t *state, sbuf_t *buf)
{
    discard            state;
    ipv4_packet_view_t carrier = {0};
    const char        *error   = pingwireIpv4PacketErrorWithView(sbufGetRawPtr(buf), sbufGetLength(buf), &carrier);
    if (error != NULL)
    {
        return error;
    }
    if (carrier.fragmented)
    {
        return "fragmented IPv4 datagram requires adapter reassembly before Ping";
    }
    if (! sbufGetRecalculateChecksum(buf) || carrier.protocol != IP_PROTO_ICMP)
    {
        return NULL;
    }
    /* Repair only the visible carrier, never the normalized native payload. */
    if (! pingwireRecalculateCarrierChecksums(buf))
    {
        return "invalid carrier geometry for visible checksum repair";
    }
    sbufSetRecalculateChecksum(buf, false);
    return NULL;
}

void pingserverHandleDownstreamPacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingserver_tstate_t *state = tunnelGetState(t);
    pingserverValidatePacketLine(t, l);

    const char *input_error = pingwirePrepareEchoRequest(buf);
    if (input_error != NULL)
    {
        pingserverDrop(t, l, buf, "outgoing", input_error);
        return;
    }

    const uint16_t sequence = (uint16_t) atomicAdd(&state->next_sequence, 1U);
    if (UNLIKELY(! pingwireBuildEchoRequest(buf, &state->wire, sequence)))
    {
        LOGF("PingServer: Echo Request build failed after successful preflight");
        abortProgramNow(1);
    }

    const uint8_t *packet         = sbufGetRawPtr(buf);
    const uint16_t payload_offset = (uint16_t) ((packet[0] & 15U) * 4U + kPingWireIcmpHeaderLength);
    const uint8_t *payload        = packet + payload_offset;
    const uint16_t payload_length = (uint16_t) (sbufGetLength(buf) - payload_offset);
    if (! pingwireOutstandingRecord(
            state->tracker, state->digest_key, state->wire.identifier, sequence, payload, payload_length))
    {
        pingserverDrop(t, l, buf, "outgoing", "failed to hash/register the outgoing Echo Request");
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}

void pingserverHandleUpstreamPacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingserver_tstate_t *state = tunnelGetState(t);
    pingserverValidatePacketLine(t, l);

    const char *input_error = pingserverConsumeCarrierChecksum(state, buf);
    if (input_error != NULL)
    {
        pingserverDrop(t, l, buf, "incoming", input_error);
        return;
    }

    if (sbufGetRecalculateChecksum(buf))
    {
        /* Unrelated traffic keeps its bytes and pending repair intent. */
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    ping_wire_envelope_t           envelope = {0};
    const ping_wire_inbound_kind_t kind =
        pingwireParseInbound(sbufGetRawPtr(buf), sbufGetLength(buf), &state->wire, &envelope);
    if (kind == kPingWireInboundUnrelated)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }
    if (kind == kPingWireInboundMalformed || kind == kPingWireInboundInvalidCarrier)
    {
        assert(envelope.error_reason != NULL);
        pingserverDrop(t, l, buf, "incoming", envelope.error_reason);
        return;
    }

    if (kind == kPingWireInboundEchoReply)
    {
        if (pingwireOutstandingConsume(state->tracker, state->digest_key, &envelope))
        {
            lineReuseBuffer(l, buf);
            return;
        }

        /* A valid but unmatched reply is unrelated IP traffic, not tunnel data. */
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    assert(kind == kPingWireInboundEchoRequest);
    const ping_wire_replay_result_t replay = pingwireReplayMark(state->tracker, state->digest_key, &envelope);
    if (replay == kPingWireReplayError)
    {
        pingserverDrop(
            t, l, buf, "incoming", "failed to hash/record the incoming Echo Request for duplicate detection");
        return;
    }

    if (state->send_replies)
    {
        /* The validated request's exact clone satisfies the reply builder and preserves every ICMP byte. */
        sbuf_t *reply = sbufDuplicateByPool(lineGetBufferPool(l), buf);
        const bool reply_built = pingwireBuildEchoReply(
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
            LOGF("PingServer: worker packet line died during generated Echo Reply callback");
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
    const bool stripped = pingwireStripEchoRequest(buf, &envelope);
    assert(stripped);
    discard stripped;

    sbufSetRecalculateChecksum(buf, false);
    /* Decoding retains receive placement; stateful consumers establish affinity. */
    tunnelNextUpStreamPayload(t, l, buf);
}
