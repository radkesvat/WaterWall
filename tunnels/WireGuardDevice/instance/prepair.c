#include "structure.h"

#include "loggers/network_logger.h"
#include "managers/node_manager.h"

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

static uint16_t wireguarddeviceCountMatchingConfiguredNext(const node_t *start_node,
                                                           wireguarddeviceTunnelMatchFn match)
{
    uint16_t      count = 0;
    uint16_t      steps = 0;
    const node_t *node  = start_node;

    while (node != NULL && node->hash_next != 0 && steps < kMaxChainLen)
    {
        node_t *next_node = nodemanagerGetConfigNodeByHash(node->node_manager_config, node->hash_next);
        if (next_node == NULL)
        {
            LOGF("Node Map Failure: node (\"%s\")->next (\"%s\") not found", node->name, node->next);
            terminateProgram(1);
        }

        if (match(next_node->instance))
        {
            count++;
        }

        node = next_node;
        steps++;
    }

    return count;
}

static uint16_t wireguarddeviceCountMatchingNext(tunnel_t *t, wireguarddeviceTunnelMatchFn match)
{
    if (t->next != NULL)
    {
        return wireguarddeviceCountMatchingTunnels(t->next, true, match);
    }

    return wireguarddeviceCountMatchingConfiguredNext(tunnelGetNode(t), match);
}

void wireguarddeviceResolveTransportSide(tunnel_t *t)
{
    wgd_tstate_t *state = tunnelGetState(t);

    if (state->transport_side_resolved)
    {
        return;
    }

    if (state->transport_direction_configured)
    {
        state->transport_side_resolved = true;
        return;
    }

    const uint16_t prev_udp_count =
        wireguarddeviceCountMatchingTunnels(t->prev, false, wireguarddeviceTunnelIsUdpStatelessSocket);
    const uint16_t next_udp_count = wireguarddeviceCountMatchingNext(t, wireguarddeviceTunnelIsUdpStatelessSocket);

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
        state->transport_side_resolved = true;
        return;
    }

    if (next_udp_count > 0)
    {
        state->transport_side_is_next = true;
        state->transport_side_resolved = true;
        return;
    }

    const bool prev_has_layer4 =
        wireguarddeviceCountMatchingTunnels(t->prev, false, wireguarddeviceTunnelHasLayer4) > 0;
    const bool next_has_layer4 = wireguarddeviceCountMatchingNext(t, wireguarddeviceTunnelHasLayer4) > 0;

    if (prev_has_layer4 && ! next_has_layer4)
    {
        state->transport_side_is_next = false;
    }

    state->transport_side_resolved = true;
}

void wireguarddeviceTunnelOnPrepair(tunnel_t *t)
{
    wireguarddeviceResolveTransportSide(t);
}
