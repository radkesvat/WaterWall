#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kPing6ClientDropLogIntervalMs = 5U * 1000U,
};

static void ping6clientValidatePacketLine(tunnel_t *t, line_t *l)
{
    ping6client_tstate_t *state = tunnelGetState(t);

    if (UNLIKELY(! lineIsAlive(l) || ! lineIsOnCurrentWorker(l) ||
                 ! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l) || state->tracker == NULL || ! state->started))
    {
        LOGF("Ping6Client: invalid worker packet-line callback");
        abortProgramNow(1);
    }
}

static void ping6clientDrop(tunnel_t *t, line_t *l, sbuf_t *buf, const char *direction, const char *reason)
{
    ping6client_tstate_t *state = tunnelGetState(t);
    if (atomicLogRateLimiterShouldLog(&state->drop_log_limiter, kPing6ClientDropLogIntervalMs))
    {
        LOGE("Ping6Client: dropping %s packet: %s (packet-bytes=%zu, max-inner-bytes=%u, overhead-bytes=%u, "
             "max-carrier-bytes=%u, headroom-bytes=%zu, required-headroom-bytes=%u)",
             direction,
             reason,
             sbufGetLength(buf),
             (unsigned int) (kMaxAllowedPacketLength - ping6wireOverhead(&state->wire)),
             (unsigned int) ping6wireOverhead(&state->wire),
             (unsigned int) kMaxAllowedPacketLength,
             sbufGetHeadroom(buf),
             (unsigned int) ping6wireOverhead(&state->wire));
    }
    lineReuseBuffer(l, buf);
}

static const char *ping6clientConsumeCarrierChecksum(ping6client_tstate_t *state, sbuf_t *buf)
{
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
    if (! sbufGetRecalculateChecksum(buf) || carrier.protocol != ping6wireCarrierProtocol(&state->wire))
    {
        return NULL;
    }
    /* Repair only the visible carrier, never the normalized native payload. */
    if (! ping6wireRecalculateCarrierChecksums(buf, &state->wire))
    {
        return "invalid carrier geometry for visible checksum repair";
    }
    sbufSetRecalculateChecksum(buf, false);
    return NULL;
}

void ping6clientEncapsulatePacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ping6client_tstate_t *state = tunnelGetState(t);
    ping6clientValidatePacketLine(t, l);

    const char *input_error = ping6wirePrepareEchoRequest(buf, &state->wire);
    if (input_error != NULL)
    {
        ping6clientDrop(t, l, buf, "outgoing", input_error);
        return;
    }

    const uint16_t sequence = (uint16_t) atomicAdd(&state->next_sequence, 1U);
    if (UNLIKELY(! ping6wireBuildEchoRequest(buf, &state->wire, sequence)))
    {
        LOGF("Ping6Client: Echo Request build failed after successful preflight");
        abortProgramNow(1);
    }

    const uint8_t *packet         = sbufGetRawPtr(buf);
    const uint16_t payload_offset = (uint16_t) ((packet[0] & 15U) * 4U + ping6wireOverhead(&state->wire) - 1U);
    const uint8_t *payload        = packet + payload_offset;
    const uint16_t payload_length = (uint16_t) (sbufGetLength(buf) - payload_offset);
    if (! pingwireOutstandingRecord(
            state->tracker, state->digest_key, state->wire.identifier, sequence, payload, payload_length))
    {
        ping6clientDrop(t, l, buf, "outgoing", "failed to hash/register the outgoing Echo Request");
        return;
    }

    tunnelNextUpStreamPayload(t, l, buf);
}

void ping6clientDecapsulatePacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ping6client_tstate_t *state = tunnelGetState(t);
    ping6clientValidatePacketLine(t, l);

    const char *input_error = ping6clientConsumeCarrierChecksum(state, buf);
    if (input_error != NULL)
    {
        ping6clientDrop(t, l, buf, "incoming", input_error);
        return;
    }
    if (sbufGetRecalculateChecksum(buf))
    {
        /* Only unrelated traffic keeps its pending repair; its possibly stale checksums are not ours to judge. */
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }

    ping_wire_envelope_t           envelope = {0};
    const ping_wire_inbound_kind_t kind =
        ping6wireParseInbound(sbufGetRawPtr(buf), sbufGetLength(buf), &state->wire, &envelope);
    if (kind == kPingWireInboundUnrelated)
    {
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }
    if (kind == kPingWireInboundMalformed || kind == kPingWireInboundInvalidCarrier)
    {
        assert(envelope.error_reason != NULL);
        ping6clientDrop(t, l, buf, "incoming", envelope.error_reason);
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
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }

    assert(kind == kPingWireInboundEchoRequest);
    const ping_wire_replay_result_t replay =
        pingwireReplayMarkForType(state->tracker, state->digest_key, &envelope, kPing6WireEchoRequest);
    if (replay == kPingWireReplayError)
    {
        ping6clientDrop(
            t, l, buf, "incoming", "failed to hash/record the incoming Echo Request for duplicate detection");
        return;
    }

    if (state->send_replies)
    {
        /* Clone before stripping the original; replies must echo every ICMPv6 byte exactly. */
        sbuf_t *reply = sbufDuplicateByPool(lineGetBufferPool(l), buf);
        // The exact clone retains the validated IPv4/ICMPv6 geometry required by the builder.
        const bool reply_built = ping6wireBuildEchoReply(
            reply,
            &state->wire,
            &envelope,
            pingwireReplyIdGeneratorNext(&state->reply_ids, wloopNowMonotonicMS(getWorkerLoop(lineGetWID(l)))));
        assert(reply_built);
        discard reply_built;

        lineRef(l);
        tunnelNextUpStreamPayload(t, l, reply);
        if (UNLIKELY(! lineIsAlive(l)))
        {
            LOGF("Ping6Client: worker packet line died during generated Echo Reply callback");
            abortProgramNow(1);
        }
        lineUnref(l);
    }

    if (replay == kPingWireReplayDuplicate)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    // The original remained locally owned and unchanged while the reply clone was forwarded.
    const bool stripped = ping6wireStripEchoRequest(buf, &envelope);
    assert(stripped);
    discard stripped;

    sbufSetRecalculateChecksum(buf, false);
    /* Decoding retains receive placement; stateful consumers establish affinity. */
    tunnelPrevDownStreamPayload(t, l, buf);
}
