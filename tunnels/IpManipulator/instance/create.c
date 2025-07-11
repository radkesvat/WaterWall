#include "structure.h"

#include "loggers/network_logger.h"

#include "tricks/protoswap/trick.h"
#include "tricks/sniblender/trick.h"

tunnel_t *ipmanipulatorCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(ipmanipulator_tstate_t), 0);

    t->fnPayloadU = &ipmanipulatorUpStreamPayload;
    t->fnPayloadD = &ipmanipulatorDownStreamPayload;
    t->onPrepair  = &ipmanipulatorOnPrepair;
    t->onStart    = &ipmanipulatorOnStart;
    t->onDestroy  = &ipmanipulatorDestroy;

    ipmanipulator_tstate_t *state = tunnelGetState(t);

    // these default values help identify if they are sot
    state->trick_proto_swap_tcp_number = -1;
    state->trick_proto_swap_udp_number = -1;

    const cJSON *settings = node->node_settings_json;

    if (getIntFromJsonObject(&state->trick_proto_swap_tcp_number, settings, "protoswap") ||
        getIntFromJsonObject(&state->trick_proto_swap_tcp_number, settings, "protoswap-tcp") ||
        getIntFromJsonObject(&state->trick_proto_swap_udp_number, settings, "protoswap-udp"))
    {
        state->trick_proto_swap = true;
    }
    if (state->trick_proto_swap)
    {
        t->fnPayloadU = &protoswaptrickUpStreamPayload;
        t->fnPayloadD = &protoswaptrickDownStreamPayload;
    }

    bool proto_sni_blender_enabled = false;
    getBoolFromJsonObject(&proto_sni_blender_enabled, settings, "sni-blender");
    if (proto_sni_blender_enabled)
    {
        if (! getIntFromJsonObject(&state->trick_sni_blender_packets_count, settings, "sni-blender-packets"))
        {
            LOGF("IpManipolator: sni-blender is enabled but field \"sni-blender-packets\" is not set");
            tunnelDestroy(t);
            return NULL;
        }

        if (state->trick_sni_blender_packets_count <= 0)
        {
            LOGF("IpManipolator: sni-blender-packets cannot be negative number");
            tunnelDestroy(t);
            return NULL;
        }

        if (state->trick_sni_blender_packets_count > kSniBlenderTrickMaxPacketsCount)
        {
            LOGF("IpManipolator: sni-blender-packets cannot be more than %d", kSniBlenderTrickMaxPacketsCount);
            tunnelDestroy(t);
            return NULL;
        }

        state->trick_sni_blender = true;
    }

    if (state->trick_sni_blender)
    {
        t->fnPayloadU = &sniblendertrickUpStreamPayload;
        t->fnPayloadD = &sniblendertrickDownStreamPayload;
    }

    return t;
}
