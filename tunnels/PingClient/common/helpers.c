#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kPingClientDropLogIntervalMs = 5U * 1000U,
};

static void pingclientValidatePacketLine(tunnel_t *t, line_t *l)
{
    pingclient_tstate_t *state = tunnelGetState(t);

    if (UNLIKELY(! lineIsAlive(l) || ! lineIsOnCurrentEventWorker(l) ||
                 ! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l) || state->tracker == NULL || ! state->started))
    {
        LOGF("PingClient: invalid worker packet-line callback");
        abortProgramNow(1);
    }
}

static void pingclientDrop(tunnel_t *t, line_t *l, sbuf_t *buf, const char *direction, const char *reason)
{
    pingclient_tstate_t *state = tunnelGetState(t);
    if (atomicLogRateLimiterShouldLog(&state->drop_log_limiter, kPingClientDropLogIntervalMs))
    {
        LOGE("PingClient: dropping %s packet: %s (packet-bytes=%u, max-inner-bytes=%u, overhead-bytes=%u, "
             "max-carrier-bytes=%u, headroom-bytes=%u, required-headroom-bytes=%u)",
             direction,
             reason,
             (unsigned int) sbufGetLength(buf),
             (unsigned int) kPingWireMaxInnerPacketLength,
             (unsigned int) kPingWireEncapsulationOverhead,
             (unsigned int) kMaxAllowedPacketLength,
             (unsigned int) sbufGetLeftCapacity(buf),
             (unsigned int) kPingWireEncapsulationOverhead);
    }
    lineReuseBuffer(l, buf);
}

static const char *pingclientConsumeInputChecksum(line_t *l, sbuf_t *buf)
{
    const bool  requested = packettunnelTakeChecksumRequest(l);
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

void pingclientEncapsulatePacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingclient_tstate_t *state = tunnelGetState(t);
    pingclientValidatePacketLine(t, l);

    const char *input_error = pingclientConsumeInputChecksum(l, buf);
    if (input_error != NULL)
    {
        pingclientDrop(t, l, buf, "outgoing", input_error);
        return;
    }

    if (sbufGetLength(buf) > kPingWireMaxInnerPacketLength)
    {
        pingclientDrop(t, l, buf, "outgoing", "IPv4 packet exceeds maximum inner size");
        return;
    }
    if (sbufGetLeftCapacity(buf) < kPingWireEncapsulationOverhead)
    {
        pingclientDrop(t, l, buf, "outgoing", "insufficient left headroom to prepend IPv4/ICMP headers");
        return;
    }

    const uint16_t sequence = (uint16_t) atomicAdd(&state->next_sequence, 1U);
    if (UNLIKELY(! pingwireBuildEchoRequest(buf, &state->wire, sequence)))
    {
        LOGF("PingClient: Echo Request build failed after successful preflight");
        abortProgramNow(1);
    }

    const uint8_t *payload        = (const uint8_t *) sbufGetRawPtr(buf) + kPingWireEncapsulationOverhead;
    const uint16_t payload_length = (uint16_t) (sbufGetLength(buf) - kPingWireEncapsulationOverhead);
    if (! pingwireOutstandingRecord(state->tracker,
                                    state->digest_key,
                                    state->wire.identifier,
                                    sequence,
                                    state->wire.peer_ipv4,
                                    state->wire.local_ipv4,
                                    payload,
                                    payload_length))
    {
        pingclientDrop(t, l, buf, "outgoing", "failed to hash/register the outgoing Echo Request");
        return;
    }

    lineSetRecalculateChecksum(l, false);
    tunnelNextUpStreamPayload(t, l, buf);
}

void pingclientDecapsulatePacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingclient_tstate_t *state = tunnelGetState(t);
    pingclientValidatePacketLine(t, l);

    const char *input_error = pingclientConsumeInputChecksum(l, buf);
    if (input_error != NULL)
    {
        pingclientDrop(t, l, buf, "incoming", input_error);
        return;
    }

    ping_wire_envelope_t           envelope = {0};
    const ping_wire_inbound_kind_t kind =
        pingwireParseInbound(sbufGetRawPtr(buf), sbufGetLength(buf), &state->wire, &envelope);
    if (kind == kPingWireInboundUnrelated)
    {
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }
    if (kind == kPingWireInboundMalformed || kind == kPingWireInboundInvalidCarrier)
    {
        assert(envelope.error_reason != NULL);
        pingclientDrop(t, l, buf, "incoming", envelope.error_reason);
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
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }

    assert(kind == kPingWireInboundEchoRequest);
    const ping_wire_replay_result_t replay = pingwireReplayMark(state->tracker, state->digest_key, &envelope);
    if (replay == kPingWireReplayError)
    {
        pingclientDrop(
            t, l, buf, "incoming", "failed to hash/record the incoming Echo Request for duplicate detection");
        return;
    }

    if (state->send_replies)
    {
        /* Clone before stripping the original; replies must echo every ICMP byte exactly. */
        sbuf_t *reply = sbufDuplicateByPool(lineGetBufferPool(l), buf);
        if (reply == NULL)
        {
            if (atomicLogRateLimiterShouldLog(&state->drop_log_limiter, kPingClientDropLogIntervalMs))
            {
                LOGE("PingClient: could not allocate an Echo Reply clone; delivering the request without an "
                     "acknowledgement (request-bytes=%u)",
                     (unsigned int) sbufGetLength(buf));
            }
        }
        else if (! pingwireBuildEchoReply(reply,
                                          &state->wire,
                                          &envelope,
                                          pingwireReplyIdGeneratorNext(
                                              &state->reply_ids, wloopNowMonotonicMS(getWorkerLoop(lineGetWID(l))))))
        {
            lineReuseBuffer(l, reply);
            reply = NULL;
            if (atomicLogRateLimiterShouldLog(&state->drop_log_limiter, kPingClientDropLogIntervalMs))
            {
                LOGE("PingClient: could not build an Echo Reply clone; delivering the request without an "
                     "acknowledgement (request-bytes=%u)",
                     (unsigned int) sbufGetLength(buf));
            }
        }

        if (reply != NULL)
        {
            lineSetRecalculateChecksum(l, false);
            lineRef(l);
            tunnelNextUpStreamPayload(t, l, reply);
            if (UNLIKELY(! lineIsAlive(l)))
            {
                LOGF("PingClient: worker packet line died during generated Echo Reply callback");
                abortProgramNow(1);
            }
            lineUnref(l);
        }
    }

    if (replay == kPingWireReplayDuplicate)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (! pingwireStripEchoRequest(buf, &envelope))
    {
        pingclientDrop(t, l, buf, "incoming", "failed to strip the validated IPv4/ICMP Echo headers");
        return;
    }

    lineSetRecalculateChecksum(l, false);
    tunnelPrevDownStreamPayload(t, l, buf);
}
