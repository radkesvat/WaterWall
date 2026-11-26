#include "PingCommon/ping_ipv4_node.h"

#include "loggers/network_logger.h"

typedef struct ping_ipv4_node_state_s
{
    ping_ipv4_config_t        wire;
    atomic_u32_t              next_sequence;
    atomic_log_rate_limiter_t drop_log;
    bool                      sequence_enabled;
    bool                      send_replies;
} ping_ipv4_node_state_t;

static bool pingipv4Transform(tunnel_t *t, line_t *l, sbuf_t *buf, bool upstream)
{
    const char *name = tunnelGetNode(t)->type;
    if (UNLIKELY(! lineIsAlive(l) || ! lineIsOnCurrentWorker(l) ||
                 ! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l)))
    {
        LOGF("%s: invalid worker packet-line callback", name);
        abortProgramNow(1);
    }

    ping_ipv4_node_state_t *state  = tunnelGetState(t);
    const bool              encode = upstream == (state->wire.role == kPingIpv4Client);
    sbuf_t                 *reply  = NULL;
    const char             *reason =
        encode ? pingipv4Encode(buf, &state->wire, state->sequence_enabled ? &state->next_sequence : NULL)
                           : pingipv4Decode(buf, &state->wire, state->send_replies ? lineGetBufferPool(l) : NULL, &reply);
    if (reason == NULL)
    {
        if (reply != NULL)
        {
            lineRef(l);
            if (upstream)
            {
                tunnelPrevDownStreamPayload(t, l, reply);
            }
            else
            {
                tunnelNextUpStreamPayload(t, l, reply);
            }
            if (UNLIKELY(! lineIsAlive(l)))
            {
                LOGF("%s: worker packet line died during generated Echo Reply callback", name);
                abortProgramNow(1);
            }
            lineUnref(l);
        }
        return true;
    }

    if (atomicLogRateLimiterShouldLog(&state->drop_log, 5000U))
    {
        if (encode)
        {
            LOGE("%s: dropping outgoing packet: %s (packet-bytes=%zu, max-inner-bytes=%u, max-carrier-bytes=%u, "
                 "headroom-bytes=%zu, required-headroom-bytes=%u)",
                 name,
                 reason,
                 sbufGetLength(buf),
                 (unsigned int) kPingIpv4MaxInnerLength,
                 (unsigned int) kMaxAllowedPacketLength,
                 sbufGetHeadroom(buf),
                 (unsigned int) kPingIpv4Overhead);
        }
        else
        {
            LOGE("%s: dropping incoming packet: %s (packet-bytes=%zu, max-inner-bytes=%u, max-carrier-bytes=%u)",
                 name,
                 reason,
                 sbufGetLength(buf),
                 (unsigned int) kPingIpv4MaxInnerLength,
                 (unsigned int) kMaxAllowedPacketLength);
        }
    }
    lineReuseBuffer(l, buf);
    return false;
}

static void pingipv4Upstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    if (pingipv4Transform(t, l, buf, true))
    {
        tunnelNextUpStreamPayload(t, l, buf);
    }
}

static void pingipv4Downstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    if (pingipv4Transform(t, l, buf, false))
    {
        tunnelPrevDownStreamPayload(t, l, buf);
    }
}

tunnel_t *pingipv4NodeCreate(node_t *node, ping_ipv4_role_t role)
{
    ping_ipv4_settings_t settings = {.wire = {.role = role}};
    if (! pingipv4ReadSettings(node, &settings))
    {
        return NULL;
    }

    tunnel_t *t = packettunnelCreate(node, sizeof(ping_ipv4_node_state_t), 0);
    if (t == NULL)
    {
        return NULL;
    }

    ping_ipv4_node_state_t *state = tunnelGetState(t);
    state->wire                   = settings.wire;
    if (settings.random_identifier)
    {
        state->wire.identifier = (uint16_t) fastRandRange32(1, UINT16_MAX);
    }
    atomicStoreU32Relaxed(&state->next_sequence, settings.sequence_start);
    state->sequence_enabled = settings.sequence_enabled;
    state->send_replies     = settings.send_replies;
    atomicLogRateLimiterInitialize(&state->drop_log);
    t->fnPayloadU = &pingipv4Upstream;
    t->fnPayloadD = &pingipv4Downstream;
    return t;
}
