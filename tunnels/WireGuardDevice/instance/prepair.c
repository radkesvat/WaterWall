#include "structure.h"

#include "loggers/network_logger.h"

typedef bool (*wireguarddeviceTunnelMatchFn)(const tunnel_t *candidate);

static bool wireguarddeviceTunnelIsUdpStatelessSocket(const tunnel_t *candidate)
{
    return (candidate != NULL) && (candidate->node != NULL) && (candidate->node->type != NULL) &&
           (stringCompare(candidate->node->type, "UdpStatelessSocket") == 0);
}

static bool wireguarddeviceTunnelHasLayer4(const tunnel_t *candidate)
{
    return (candidate != NULL) && (candidate->node != NULL) &&
           ((candidate->node->layer_group & kNodeLayer4) == kNodeLayer4);
}

static uint16_t wireguarddeviceCountMatchingTunnels(const tunnel_t *start, bool toward_next,
                                                    wireguarddeviceTunnelMatchFn match)
{
    uint16_t        count     = 0;
    uint16_t        steps     = 0;
    const tunnel_t *candidate = start;

    while (candidate != NULL && steps < kMaxChainLen)
    {
        if (match(candidate))
        {
            count++;
        }

        candidate = toward_next ? candidate->next : candidate->prev;
        steps++;
    }

    return count;
}

void wireguarddeviceTunnelOnPrepair(tunnel_t *t)
{
    wgd_tstate_t *state = tunnelGetState(t);

    if (state->transport_direction_configured)
    {
        return;
    }

    const uint16_t prev_udp_count =
        wireguarddeviceCountMatchingTunnels(t->prev, false, wireguarddeviceTunnelIsUdpStatelessSocket);
    const uint16_t next_udp_count =
        wireguarddeviceCountMatchingTunnels(t->next, true, wireguarddeviceTunnelIsUdpStatelessSocket);

    state->transport_side_is_next = true;

    if (prev_udp_count > 0 && next_udp_count > 0)
    {
        LOGF("WireGuardDevice: settings->transport-direction is required when UdpStatelessSocket is reachable in "
             "both directions");
        terminateProgram(1);
    }

    if (prev_udp_count > 0)
    {
        state->transport_side_is_next = false;
        return;
    }

    if (next_udp_count > 0)
    {
        state->transport_side_is_next = true;
        return;
    }

    const bool prev_has_layer4 =
        wireguarddeviceCountMatchingTunnels(t->prev, false, wireguarddeviceTunnelHasLayer4) > 0;
    const bool next_has_layer4 =
        wireguarddeviceCountMatchingTunnels(t->next, true, wireguarddeviceTunnelHasLayer4) > 0;

    if (prev_has_layer4 && ! next_has_layer4)
    {
        state->transport_side_is_next = false;
    }
}
