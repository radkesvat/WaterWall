#include "structure.h"

#include "loggers/network_logger.h"

#include "tricks/protoswap/trick.h"
#include "tricks/sniblender/trick.h"
#include "tricks/tcpbitchange/trick.h"

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
        return t;
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
        return t;
    }

    state->up_tcp_bit_cwr_action =
        parseDynamicStrValueFromJsonObject(settings, "up-tcp-bit-cwr", 10, "off", "on", "swap-cwr", "swap-ece",
                                           "swap-urg", "swap-ack", "swap-psh", "swap-rst", "swap-syn", "swap-fin")
            .integer;

    state->up_tcp_bit_ece_action =
        parseDynamicStrValueFromJsonObject(settings, "up-tcp-bit-ece", 10, "off", "on", "swap-cwr", "swap-ece",
                                           "swap-urg", "swap-ack", "swap-psh", "swap-rst", "swap-syn", "swap-fin")
            .integer;

    state->up_tcp_bit_urg_action =
        parseDynamicStrValueFromJsonObject(settings, "up-tcp-bit-urg", 10, "off", "on", "swap-cwr", "swap-ece",
                                           "swap-urg", "swap-ack", "swap-psh", "swap-rst", "swap-syn", "swap-fin")
            .integer;
    state->up_tcp_bit_ack_action =
        parseDynamicStrValueFromJsonObject(settings, "up-tcp-bit-ack", 10, "off", "on", "swap-cwr", "swap-ece",
                                           "swap-urg", "swap-ack", "swap-psh", "swap-rst", "swap-syn", "swap-fin")
            .integer;
    state->up_tcp_bit_psh_action =
        parseDynamicStrValueFromJsonObject(settings, "up-tcp-bit-psh", 10, "off", "on", "swap-cwr", "swap-ece",
                                           "swap-urg", "swap-ack", "swap-psh", "swap-rst", "swap-syn", "swap-fin")
            .integer;
    state->up_tcp_bit_rst_action =
        parseDynamicStrValueFromJsonObject(settings, "up-tcp-bit-rst", 10, "off", "on", "swap-cwr", "swap-ece",
                                           "swap-urg", "swap-ack", "swap-psh", "swap-rst", "swap-syn", "swap-fin")
            .integer;
    state->up_tcp_bit_syn_action =
        parseDynamicStrValueFromJsonObject(settings, "up-tcp-bit-syn", 10, "off", "on", "swap-cwr", "swap-ece",
                                           "swap-urg", "swap-ack", "swap-psh", "swap-rst", "swap-syn", "swap-fin")
            .integer;
    state->up_tcp_bit_fin_action =
        parseDynamicStrValueFromJsonObject(settings, "up-tcp-bit-fin", 10, "off", "on", "swap-cwr", "swap-ece",
                                           "swap-urg", "swap-ack", "swap-psh", "swap-rst", "swap-syn", "swap-fin")
            .integer;

    state->down_tcp_bit_cwr_action =
        parseDynamicStrValueFromJsonObject(settings, "dw-tcp-bit-cwr", 10, "off", "on", "swap-cwr", "swap-ece",
                                           "swap-urg", "swap-ack", "swap-psh", "swap-rst", "swap-syn", "swap-fin")
            .integer;

    state->down_tcp_bit_ece_action =
        parseDynamicStrValueFromJsonObject(settings, "dw-tcp-bit-ece", 10, "off", "on", "swap-cwr", "swap-ece",
                                           "swap-urg", "swap-ack", "swap-psh", "swap-rst", "swap-syn", "swap-fin")
            .integer;

    state->down_tcp_bit_urg_action =
        parseDynamicStrValueFromJsonObject(settings, "dw-tcp-bit-urg", 10, "off", "on", "swap-cwr", "swap-ece",
                                           "swap-urg", "swap-ack", "swap-psh", "swap-rst", "swap-syn", "swap-fin")
            .integer;
    state->down_tcp_bit_ack_action =
        parseDynamicStrValueFromJsonObject(settings, "dw-tcp-bit-ack", 10, "off", "on", "swap-cwr", "swap-ece",
                                           "swap-urg", "swap-ack", "swap-psh", "swap-rst", "swap-syn", "swap-fin")
            .integer;
    state->down_tcp_bit_psh_action =
        parseDynamicStrValueFromJsonObject(settings, "dw-tcp-bit-psh", 10, "off", "on", "swap-cwr", "swap-ece",
                                           "swap-urg", "swap-ack", "swap-psh", "swap-rst", "swap-syn", "swap-fin")
            .integer;
    state->down_tcp_bit_rst_action =
        parseDynamicStrValueFromJsonObject(settings, "dw-tcp-bit-rst", 10, "off", "on", "swap-cwr", "swap-ece",
                                           "swap-urg", "swap-ack", "swap-psh", "swap-rst", "swap-syn", "swap-fin")
            .integer;
    state->down_tcp_bit_syn_action =
        parseDynamicStrValueFromJsonObject(settings, "dw-tcp-bit-syn", 10, "off", "on", "swap-cwr", "swap-ece",
                                           "swap-urg", "swap-ack", "swap-psh", "swap-rst", "swap-syn", "swap-fin")
            .integer;
    state->down_tcp_bit_fin_action =
        parseDynamicStrValueFromJsonObject(settings, "dw-tcp-bit-fin", 10, "off", "on", "swap-cwr", "swap-ece",
                                           "swap-urg", "swap-ack", "swap-psh", "swap-rst", "swap-syn", "swap-fin")
            .integer;

    if (state->down_tcp_bit_cwr_action != kDvsNoAction || state->down_tcp_bit_ece_action != kDvsNoAction ||
        state->down_tcp_bit_urg_action != kDvsNoAction || state->down_tcp_bit_ack_action != kDvsNoAction ||
        state->down_tcp_bit_psh_action != kDvsNoAction || state->down_tcp_bit_rst_action != kDvsNoAction ||
        state->down_tcp_bit_syn_action != kDvsNoAction || state->down_tcp_bit_fin_action != kDvsNoAction ||
        state->up_tcp_bit_cwr_action != kDvsNoAction || state->up_tcp_bit_ece_action != kDvsNoAction ||
        state->up_tcp_bit_urg_action != kDvsNoAction || state->up_tcp_bit_ack_action != kDvsNoAction ||
        state->up_tcp_bit_psh_action != kDvsNoAction || state->up_tcp_bit_rst_action != kDvsNoAction ||
        state->up_tcp_bit_syn_action != kDvsNoAction || state->up_tcp_bit_fin_action != kDvsNoAction

    )
    {
        state->trick_tcp_bit_changes = true;
        t->fnPayloadU                = &tcpbitchangetrickUpStreamPayload;
        t->fnPayloadD                = &tcpbitchangetrickDownStreamPayload;
        return t;
    }

    LOGF("IpManipolator : No tricks are enabled, nothing to do");
    tunnelDestroy(t);
    return NULL;
}
