#include "structure.h"

#include "loggers/network_logger.h"

void junkdatagramsenderLinestateInitialize(junkdatagramsender_lstate_t *ls, const junkdatagramsender_tstate_t *ts)
{
    *ls = (junkdatagramsender_lstate_t) {
        .remaining_resend_again_times = ts->resend_again_times,
    };
}

void junkdatagramsenderLinestateDestroy(junkdatagramsender_lstate_t *ls)
{
    memorySet(ls, 0, tunnelGetCorrectAlignedLineStateSize(sizeof(junkdatagramsender_lstate_t)));
}

static uint32_t junkdatagramsenderProtocolCount(uint64_t mask)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < (uint32_t) kJunkDatagramSenderProtocolCount; ++i)
    {
        if ((mask & (UINT64_C(1) << i)) != 0)
        {
            ++count;
        }
    }
    return count;
}

static junkdatagramsender_protocol_t junkdatagramsenderPickProtocol(uint64_t mask)
{
    uint32_t selected_count = junkdatagramsenderProtocolCount(mask);
    assert(selected_count > 0);

    uint32_t selected_index = fastRand32() % selected_count;
    for (uint32_t i = 0; i < (uint32_t) kJunkDatagramSenderProtocolCount; ++i)
    {
        if ((mask & (UINT64_C(1) << i)) == 0)
        {
            continue;
        }
        if (selected_index == 0)
        {
            return (junkdatagramsender_protocol_t) i;
        }
        --selected_index;
    }

    return kJunkDatagramSenderProtocolDns;
}

static void junkdatagramsenderDelayedUpstreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tunnelNextUpStreamPayload(t, l, buf);
}

static void junkdatagramsenderDelayedDownstreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tunnelPrevDownStreamPayload(t, l, buf);
}

static LineTaskFnWithBuf junkdatagramsenderDelayedPayloadFn(junkdatagramsender_direction_t direction)
{
    return direction == kJunkDatagramSenderDirectionUpstream ? junkdatagramsenderDelayedUpstreamPayload
                                                             : junkdatagramsenderDelayedDownstreamPayload;
}

static bool junkdatagramsenderGeneratePayload(tunnel_t *t, line_t *l, sbuf_t *buf,
                                              junkdatagramsender_protocol_t protocol)
{
    discard t;

    const junkdatagramsender_module_descriptor_t *descriptor = junkdatagramsenderFindProtocolDescriptor(protocol);
    if (descriptor == NULL || descriptor->generate == NULL)
    {
        LOGW("JunkDatagramSender: selected protocol has no generator");
        lineReuseBuffer(l, buf);
        return false;
    }

    junkdatagramsender_module_args_t args = {
        .protocol        = protocol,
        .protocol_name   = descriptor->canonical_name,
        .min_packet_size = kJunkDatagramSenderDefaultMinPacketSize,
        .max_packet_size = kJunkDatagramSenderDefaultMaxPacketSize,
    };

    if (! descriptor->generate(buf, &args) || sbufGetLength(buf) == 0)
    {
        lineReuseBuffer(l, buf);
        return false;
    }

    return true;
}

static bool junkdatagramsenderSendOne(tunnel_t *t, line_t *l, junkdatagramsender_direction_t direction)
{
    junkdatagramsender_tstate_t *ts = tunnelGetState(t);

    if (ts->selected_protocol_mask == 0)
    {
        return true;
    }

    sbuf_t *buf = bufferpoolGetLargeBuffer(lineGetBufferPool(l));
    sbufSetLength(buf, 0);

    junkdatagramsender_protocol_t protocol = junkdatagramsenderPickProtocol(ts->selected_protocol_mask);
    if (! junkdatagramsenderGeneratePayload(t, l, buf, protocol))
    {
        return true;
    }

    if (ts->keep_sending_max_ms > 0)
    {
        sbuf_t  *scheduled = sbufDuplicateByPool(lineGetBufferPool(l), buf);
        uint32_t delay_ms  = fastRandRange32(1, ts->keep_sending_max_ms);
        lineScheduleDelayedTaskWithBuf(l, junkdatagramsenderDelayedPayloadFn(direction), delay_ms, t, scheduled);
    }

    if (direction == kJunkDatagramSenderDirectionUpstream)
    {
        tunnelNextUpStreamPayload(t, l, buf);
    }
    else
    {
        tunnelPrevDownStreamPayload(t, l, buf);
    }

    return lineIsAlive(l);
}

bool junkdatagramsenderSendJunk(tunnel_t *t, line_t *l, junkdatagramsender_direction_t direction)
{
    junkdatagramsender_tstate_t *ts = tunnelGetState(t);

    if (ts->packet_count_max == 0 || ts->selected_protocol_mask == 0)
    {
        return true;
    }

    uint32_t packet_count = fastRandRange32(ts->packet_count_min, ts->packet_count_max);
    for (uint32_t i = 0; i < packet_count; ++i)
    {
        if (! lineIsAlive(l))
        {
            return false;
        }

        if (! junkdatagramsenderSendOne(t, l, direction))
        {
            return false;
        }
    }

    return lineIsAlive(l);
}
