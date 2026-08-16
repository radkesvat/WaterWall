#include "structure.h"

#include "TlsClient/interface.h"
#include "loggers/network_logger.h"

#include "tricks/echsnitrick/trick.h"
#include "tricks/firstsni/trick.h"
#include "tricks/overlapsni/trick.h"
#include "tricks/protoswap/trick.h"
#include "tricks/smugglefin/trick.h"
#include "tricks/smugglesni/trick.h"
#include "tricks/sniblender/trick.h"
#include "tricks/synfinsni/trick.h"
#include "tricks/tcpbitchange/trick.h"

static bool parseTcpBitActionField(enum tcp_bit_action_dynamic_value *dest, const cJSON *settings, const char *key)
{
    dynamic_value_t action = parseDynamicStrValueFromJsonObject(settings,
                                                                key,
                                                                11,
                                                                "off",
                                                                "on",
                                                                "toggle",
                                                                "packet->cwr",
                                                                "packet->ece",
                                                                "packet->urg",
                                                                "packet->ack",
                                                                "packet->psh",
                                                                "packet->rst",
                                                                "packet->syn",
                                                                "packet->fin");

    if (action.status == kDvsConstant)
    {
        if (action.string != NULL && (stringCompare((const char *) action.string, "flip") == 0 ||
                                      stringCompare((const char *) action.string, "switch") == 0))
        {
            *dest = kDvsToggle;
            dynamicvalueDestroy(action);
            return true;
        }

        LOGF("IpManipulator: settings->%s has invalid value", key);
        dynamicvalueDestroy(action);
        return false;
    }

    *dest = (enum tcp_bit_action_dynamic_value) action.status;
    dynamicvalueDestroy(action);
    return true;
}

/*
 * The one authoritative compatibility matrix. Every rule below is independent
 * of TCP-bit actions, so none of them may be moved behind the upstream-action
 * early return at the end.
 */
ipmanipulator_config_validation_e ipmanipulatorValidateTrickCompatibility(const ipmanipulator_tstate_t *state)
{
    uint32_t stateful_sni_count = (state->trick_first_sni ? 1U : 0U) + (state->trick_smuggle_sni ? 1U : 0U) +
                                  (state->trick_overlap_sni ? 1U : 0U) + (state->trick_synfin_sni ? 1U : 0U) +
                                  (state->trick_ech_sni ? 1U : 0U);

    if (stateful_sni_count > 1U)
    {
        return kIpManipulatorConfigRejectMultipleStatefulSni;
    }

    /*
     * A stateful SNI trick sends its held originals and crafted transcript
     * straight to the next tunnel, so a later same-instance stage would only
     * see the flow's untouched packets. Splitting the operations over two
     * chained nodes is what actually shapes the trick's own output.
     */
    if (stateful_sni_count == 1U && state->trick_sni_blender)
    {
        return kIpManipulatorConfigRejectSniBlenderWithStatefulSni;
    }

    if (stateful_sni_count == 1U && state->trick_packet_duplicate)
    {
        return kIpManipulatorConfigRejectPacketDuplicateWithStatefulSni;
    }

    /*
     * SNI Blender emits IPv4 fragments for the real ClientHello, while port
     * ghost deliberately skips fragments in both apply and restore paths.
     * Accepting the pair would ghost the SYN and ordinary packets but not the
     * ClientHello fragments of the very same flow.
     */
    if (state->trick_sni_blender && (state->trick_source_port_ghost || state->trick_dest_port_ghost))
    {
        return kIpManipulatorConfigRejectSniBlenderWithPortGhost;
    }

    if (! tcpbitchangetrickHasUpstreamActions(state))
    {
        /*
         * Downstream-only actions never touch the upstream flow-opening SYN or
         * the upstream ClientHello, and preservation without any action is a
         * no-op encoder that appends nothing.
         */
        return kIpManipulatorConfigValid;
    }

    if (stateful_sni_count > 0U)
    {
        return kIpManipulatorConfigRejectUpstreamTcpBitWithStatefulSni;
    }

    if (state->trick_preserve_tcp_bitflags && state->trick_sni_blender)
    {
        return kIpManipulatorConfigRejectPreservedTcpBitWithSniBlender;
    }

    return kIpManipulatorConfigValid;
}

static bool reportTrickCompatibility(const ipmanipulator_tstate_t *state)
{
    switch (ipmanipulatorValidateTrickCompatibility(state))
    {
    case kIpManipulatorConfigRejectUpstreamTcpBitWithStatefulSni:
        LOGF("IpManipulator: upstream TCP-bit actions (\"up-tcp-bit-*\") cannot be combined with the stateful SNI "
             "tricks \"first-sni\", \"smuggle-sni\", \"overlap-sni\", \"synfin-sni\" or \"ech-sni-trick\"; upstream "
             "TCP-bit actions run before stateful SNI inspection and their generated or replayed packets do not "
             "re-enter TCP-bit processing. Put the operations in separate IpManipulator nodes");
        return false;

    case kIpManipulatorConfigRejectPreservedTcpBitWithSniBlender:
        LOGF("IpManipulator: \"preserve-tcp-bitflags\" with an upstream TCP-bit action cannot be combined with "
             "\"sni-blender\"; the preserved-flag byte is appended before SNI Blender creates IPv4 fragments and the "
             "peer restoration path skips fragments. Put the operations in separate IpManipulator nodes");
        return false;

    case kIpManipulatorConfigRejectMultipleStatefulSni:
        LOGF("IpManipulator: only one of the stateful SNI tricks \"first-sni\", \"smuggle-sni\", \"overlap-sni\", "
             "\"synfin-sni\" or \"ech-sni-trick\" may be enabled in one IpManipulator node; each one owns the same "
             "flow's ClientHello and emits its own transcript for it. Put the operations in separate IpManipulator "
             "nodes");
        return false;

    case kIpManipulatorConfigRejectSniBlenderWithStatefulSni:
        LOGF("IpManipulator: \"sni-blender\" cannot be combined with the stateful SNI tricks \"first-sni\", "
             "\"smuggle-sni\", \"overlap-sni\", \"synfin-sni\" or \"ech-sni-trick\" in one node; a stateful SNI trick "
             "emits its packets directly and they never reach a later same-instance blender stage. Put the operations "
             "in separate IpManipulator nodes, with the stateful SNI node first and the \"sni-blender\" node as its "
             "next node");
        return false;

    case kIpManipulatorConfigRejectPacketDuplicateWithStatefulSni:
        LOGF("IpManipulator: \"packet-duplicate\" cannot be combined with the stateful SNI tricks \"first-sni\", "
             "\"smuggle-sni\", \"overlap-sni\", \"synfin-sni\" or \"ech-sni-trick\" in one node; a stateful SNI trick "
             "emits its packets directly and they never reach a later same-instance duplication stage. Put the "
             "operations in separate IpManipulator nodes, with the stateful SNI node first and the "
             "\"packet-duplicate\" node as its next node");
        return false;

    case kIpManipulatorConfigRejectSniBlenderWithPortGhost:
        LOGF("IpManipulator: \"sni-blender\" cannot be combined with \"source-port-ghost\" or \"dest-port-ghost\" "
             "in one node; SNI Blender creates IPv4 fragments while port ghost deliberately skips fragments in both "
             "directions. Choose one of these tricks for the node");
        return false;

    case kIpManipulatorConfigValid:
    default:
        return true;
    }
}

static bool validateProtocolSwapNumber(const char *key, int protocol_number)
{
    if (protocol_number < 0 || protocol_number > UINT8_MAX)
    {
        LOGF("IpManipulator: settings->%s must be between 0 and 255", key);
        return false;
    }

    if (protocol_number == IPPROTO_TCP || protocol_number == IPPROTO_UDP)
    {
        LOGF("IpManipulator: settings->%s must not reuse a literal TCP/UDP protocol number", key);
        return false;
    }

    return true;
}

static bool createInternalTlsClient(tunnel_t *t, node_t *owner, const char *sni, const char *name_suffix,
                                    tunnel_t **role_tunnel)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    assert(state->internal_tls_client_settings == NULL);
    assert(state->internal_tls_client_tunnel == NULL);
    assert(*role_tunnel == NULL);

    state->internal_tls_client_settings = cJSON_CreateObject();
    if (state->internal_tls_client_settings == NULL ||
        cJSON_AddStringToObject(state->internal_tls_client_settings, "sni", sni) == NULL ||
        cJSON_AddBoolToObject(state->internal_tls_client_settings, "x25519mlkem768", false) == NULL)
    {
        LOGF("IpManipulator: failed to build internal TlsClient settings");
        return false;
    }

    if (! nodeConfigureChild(&state->internal_tls_client_node,
                             nodeTlsClientGet(),
                             owner,
                             name_suffix,
                             kNodeChildLinkNone,
                             state->internal_tls_client_settings))
    {
        LOGF("IpManipulator: failed to configure internal TlsClient child node");
        return false;
    }

    state->internal_tls_client_node.flags |= kNodeFlagNoChain;
    state->internal_tls_client_node.can_have_next = false;
    state->internal_tls_client_tunnel             = nodemanagerCreateTunnelInstance(&state->internal_tls_client_node);
    if (state->internal_tls_client_tunnel == NULL)
    {
        LOGF("IpManipulator: failed to create internal TlsClient child tunnel");
        return false;
    }

    state->internal_tls_client_node.instance = state->internal_tls_client_tunnel;
    *role_tunnel                             = state->internal_tls_client_tunnel;
    return true;
}

static bool createConfiguredTlsClient(tunnel_t *t, node_t *node)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (state->trick_smuggle_sni)
    {
        return createInternalTlsClient(t,
                                       node,
                                       state->trick_smuggle_sni_value,
                                       ".smuggle-sni-tls-client",
                                       &state->trick_real_sni_tls_client_tunnel);
    }

    if (state->trick_overlap_sni)
    {
        return createInternalTlsClient(t,
                                       node,
                                       state->trick_overlap_sni_value,
                                       ".overlap-sni-tls-client",
                                       &state->trick_overlap_sni_tls_client_tunnel);
    }

    if (state->trick_synfin_sni)
    {
        return createInternalTlsClient(t,
                                       node,
                                       state->trick_synfin_sni_value,
                                       ".synfin-sni-tls-client",
                                       &state->trick_synfin_sni_tls_client_tunnel);
    }

    return true;
}

static bool parseStatefulFlowLimit(ipmanipulator_tstate_t *state, const cJSON *settings)
{
    int limit = kIpManipulatorFlowLimitDefault;

    if (getIntFromJsonObject(&limit, settings, "stateful-flow-limit") &&
        (limit < kIpManipulatorFlowLimitMin || limit > kIpManipulatorFlowLimitMax))
    {
        LOGF("IpManipulator: settings->stateful-flow-limit must be between %d and %d",
             kIpManipulatorFlowLimitMin,
             kIpManipulatorFlowLimitMax);
        return false;
    }

    state->trick_stateful_flow_limit = (uint32_t) limit;
    return true;
}

static bool initializeStatefulTrickTables(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    return (! state->trick_first_sni || firstsnitrickInitializeState(t)) &&
           (! state->trick_smuggle_sni || smugglesnitrickInitializeState(t)) &&
           (! state->trick_overlap_sni || overlapsnitrickInitializeState(t)) &&
           (! state->trick_synfin_sni || synfinsnitrickInitializeState(t)) &&
           (! state->trick_ech_sni || echsnitrickInitializeState(t)) &&
           (! state->trick_smuggle_fin || smugglefintrickInitializeState(t));
}

tunnel_t *ipmanipulatorCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(ipmanipulator_tstate_t), 0);
    if (! t)
    {
        return NULL;
    }

    t->fnInitU          = &ipmanipulatorUpStreamInit;
    t->fnInitD          = &ipmanipulatorDownStreamInit;
    t->fnPayloadU       = &ipmanipulatorUpStreamPayload;
    t->fnPayloadD       = &ipmanipulatorDownStreamPayload;
    t->onChain          = &ipmanipulatorOnChain;
    t->onPrepare        = &ipmanipulatorOnPrepair;
    t->onStart          = &ipmanipulatorOnStart;
    t->onQuiesceRequest = &ipmanipulatorOnQuiesceRequest;
    t->onWorkerQuiesce  = &ipmanipulatorOnWorkerQuiesce;
    t->onQuiesceWait    = &ipmanipulatorOnQuiesceWait;
    t->onWorkerStop     = &ipmanipulatorOnWorkerStop;
    t->onStop           = &ipmanipulatorOnStop;
    t->onDestroy        = &ipmanipulatorDestroy;

    ipmanipulator_tstate_t *state    = tunnelGetState(t);
    const cJSON            *settings = node->node_settings_json;

    state->trick_proto_swap_tcp_number           = -1;
    state->trick_proto_swap_udp_number           = -1;
    state->trick_overlap_sni_syn_ttl             = -1;
    state->trick_synfin_sni_syn_ttl              = -1;
    state->trick_synfin_sni_fin_ttl              = -1;
    state->trick_synfin_sni_fake_ttl             = -1;
    state->trick_synfin_sni_additional_range_min = 0;
    state->trick_synfin_sni_additional_range_max = 0;
    state->trick_overlap_sni_hold_timeout_ms     = 50;
    state->trick_synfin_sni_hold_timeout_ms      = 50;
    state->trick_ech_sni_shard1_delay_ms         = 0;
    state->trick_ech_sni_shard2_delay_ms         = 0;
    atomicStoreU64Relaxed(&state->delay_barrier_next_generation, 0);
    atomicLogRateLimiterInitialize(&state->egress_warning_limiter);
    atomicLogRateLimiterInitialize(&state->worker_mismatch_guidance_limiter);

    if (! parseStatefulFlowLimit(state, settings))
    {
        tunnelDestroy(t);
        return NULL;
    }

    /*
     * "protoswap-tcp-2" alternated between two TCP replacement numbers, which
     * split one IPv4 datagram across two mappings. It is gone; a stale key is
     * rejected instead of ignored so an old configuration cannot silently do
     * something different from what it says.
     */
    if (cJSON_GetObjectItemCaseSensitive(settings, "protoswap-tcp-2") != NULL)
    {
        LOGF("IpManipulator: settings->protoswap-tcp-2 has been removed; protocol swap now uses one reversible TCP "
             "replacement number, so configure only \"protoswap-tcp\"");
        tunnelDestroy(t);
        return NULL;
    }

    bool has_proto_swap_legacy = getIntFromJsonObject(&state->trick_proto_swap_tcp_number, settings, "protoswap");
    bool has_proto_swap_tcp    = getIntFromJsonObject(&state->trick_proto_swap_tcp_number, settings, "protoswap-tcp");
    bool has_proto_swap_udp    = getIntFromJsonObject(&state->trick_proto_swap_udp_number, settings, "protoswap-udp");

    const char *proto_swap_tcp_key = has_proto_swap_tcp ? "protoswap-tcp" : "protoswap";

    if (((has_proto_swap_legacy || has_proto_swap_tcp) &&
         ! validateProtocolSwapNumber(proto_swap_tcp_key, state->trick_proto_swap_tcp_number)) ||
        (has_proto_swap_udp && ! validateProtocolSwapNumber("protoswap-udp", state->trick_proto_swap_udp_number)))
    {
        tunnelDestroy(t);
        return NULL;
    }

    state->trick_proto_swap = has_proto_swap_legacy || has_proto_swap_tcp || has_proto_swap_udp;

    bool tcp_swap_enabled = has_proto_swap_legacy || has_proto_swap_tcp;
    if (tcp_swap_enabled && has_proto_swap_udp &&
        state->trick_proto_swap_udp_number == state->trick_proto_swap_tcp_number)
    {
        LOGF("IpManipulator: TCP and UDP protocol-swap mappings must remain unambiguous");
        tunnelDestroy(t);
        return NULL;
    }

    bool sni_blender_enabled = false;
    getBoolFromJsonObject(&sni_blender_enabled, settings, "sni-blender");
    if (sni_blender_enabled)
    {
        if (! getIntFromJsonObject(&state->trick_sni_blender_packets_count, settings, "sni-blender-packets"))
        {
            LOGF("IpManipulator: sni-blender is enabled but field \"sni-blender-packets\" is not set");
            tunnelDestroy(t);
            return NULL;
        }

        /*
         * One "fragment" is the packet itself, so the trick only means anything
         * from two upwards. The runtime keeps its own planned_count <= 1 bypass
         * for packets that cannot actually be divided.
         */
        if (state->trick_sni_blender_packets_count < kSniBlenderTrickMinPacketsCount ||
            state->trick_sni_blender_packets_count > kSniBlenderTrickMaxPacketsCount)
        {
            LOGF("IpManipulator: sni-blender-packets must be between %d and %d",
                 kSniBlenderTrickMinPacketsCount,
                 kSniBlenderTrickMaxPacketsCount);
            tunnelDestroy(t);
            return NULL;
        }

        state->trick_sni_blender = true;
    }

    if (getIntFromJsonObject(&state->trick_packet_duplicate_count, settings, "packet-duplicate"))
    {
        if (state->trick_packet_duplicate_count <= 0 ||
            state->trick_packet_duplicate_count > kPacketDuplicateTrickMaxCount)
        {
            LOGF("IpManipulator: packet-duplicate must be between 1 and %d", kPacketDuplicateTrickMaxCount);
            tunnelDestroy(t);
            return NULL;
        }

        state->trick_packet_duplicate = true;
    }

    bool preserve_tcp_bitflags_enabled = false;
    getBoolFromJsonObject(&preserve_tcp_bitflags_enabled, settings, "bit-transport");
    getBoolFromJsonObject(&preserve_tcp_bitflags_enabled, settings, "carry-original-tcp-flags");
    getBoolFromJsonObject(&preserve_tcp_bitflags_enabled, settings, "preserve-tcp-bitflags");
    state->trick_preserve_tcp_bitflags = preserve_tcp_bitflags_enabled;

    bool source_port_ghost_enabled = false;
    bool dest_port_ghost_enabled   = false;
    getBoolFromJsonObject(&source_port_ghost_enabled, settings, "source-port-ghost");
    getBoolFromJsonObject(&dest_port_ghost_enabled, settings, "dest-port-ghost");
    state->trick_source_port_ghost = source_port_ghost_enabled;
    state->trick_dest_port_ghost   = dest_port_ghost_enabled;

    state->trick_first_sni_count           = 1;
    state->trick_first_sni_replay_delay_ms = 0;
    state->trick_first_sni_final_delay_ms  = 0;
    state->trick_first_sni_ttl             = -1;

    bool has_first_sni = getStringFromJsonObject(&state->trick_first_sni_value, settings, "first-sni");
    if (has_first_sni)
    {
        int    first_sni_count = 1;
        int    replay_delay_ms = 0;
        int    final_delay_ms  = 0;
        size_t first_sni_len   = stringLength(state->trick_first_sni_value);

        if (first_sni_len == 0)
        {
            LOGF("IpManipulator: first-sni field \"first-sni\" must not be empty");
            tunnelDestroy(t);
            return NULL;
        }

        if (first_sni_len > UINT16_MAX)
        {
            LOGF("IpManipulator: first-sni field \"first-sni\" must fit in 16-bit TLS length fields");
            tunnelDestroy(t);
            return NULL;
        }

        if (getIntFromJsonObject(&first_sni_count, settings, "first-sni-count"))
        {
            if (first_sni_count <= 0 || first_sni_count > kFirstSniTrickMaxCount)
            {
                LOGF("IpManipulator: first-sni field \"first-sni-count\" must be between 1 and %d",
                     kFirstSniTrickMaxCount);
                tunnelDestroy(t);
                return NULL;
            }
        }

        if (getIntFromJsonObject(&replay_delay_ms, settings, "first-sni-replay-delay"))
        {
            if (replay_delay_ms < 0)
            {
                LOGF("IpManipulator: first-sni field \"first-sni-replay-delay\" must be zero or greater");
                tunnelDestroy(t);
                return NULL;
            }
        }

        if (getIntFromJsonObject(&final_delay_ms, settings, "first-sni-final-delay"))
        {
            if (final_delay_ms < 0)
            {
                LOGF("IpManipulator: first-sni field \"first-sni-final-delay\" must be zero or greater");
                tunnelDestroy(t);
                return NULL;
            }
        }

        if (first_sni_count > 1 && replay_delay_ms > 0 &&
            ((uint64_t) (first_sni_count - 1) * (uint64_t) replay_delay_ms) > UINT32_MAX)
        {
            LOGF("IpManipulator: first-sni replay schedule exceeds supported delay range");
            tunnelDestroy(t);
            return NULL;
        }

        uint64_t first_sni_replay_span_ms =
            (first_sni_count > 1) ? ((uint64_t) (first_sni_count - 1) * (uint64_t) replay_delay_ms) : 0;
        if (first_sni_replay_span_ms + (uint64_t) final_delay_ms > UINT32_MAX)
        {
            LOGF("IpManipulator: first-sni combined replay and final delay exceeds supported delay range");
            tunnelDestroy(t);
            return NULL;
        }

        if (getIntFromJsonObject(&state->trick_first_sni_ttl, settings, "first-sni-ttl"))
        {
            if (state->trick_first_sni_ttl < 0 || state->trick_first_sni_ttl > UINT8_MAX)
            {
                LOGF("IpManipulator: first-sni field \"first-sni-ttl\" must be between 0 and 255");
                tunnelDestroy(t);
                return NULL;
            }
        }

        getBoolFromJsonObject(&state->trick_first_sni_random_tcp_sequence, settings, "first-sni-random-tcp-sequence");

        state->trick_first_sni_value_len       = (uint16_t) first_sni_len;
        state->trick_first_sni_count           = (uint32_t) first_sni_count;
        state->trick_first_sni_replay_delay_ms = (uint32_t) replay_delay_ms;
        state->trick_first_sni_final_delay_ms  = (uint32_t) final_delay_ms;
        state->trick_first_sni                 = true;
    }

    bool has_smuggle_sni = getStringFromJsonObject(&state->trick_smuggle_sni_value, settings, "smuggle-sni");
    if (has_smuggle_sni)
    {
        char  *real_sni_upstream_node_name = NULL;
        int    smuggle_sni_delay_ms        = 0;
        size_t smuggle_sni_len             = stringLength(state->trick_smuggle_sni_value);

        if (smuggle_sni_len == 0)
        {
            LOGF("IpManipulator: smuggle-sni field \"smuggle-sni\" must not be empty");
            tunnelDestroy(t);
            return NULL;
        }

        if (smuggle_sni_len > UINT16_MAX)
        {
            LOGF("IpManipulator: smuggle-sni field \"smuggle-sni\" must fit in 16-bit TLS length fields");
            tunnelDestroy(t);
            return NULL;
        }

        if (! nodeHasNext(node))
        {
            LOGF("IpManipulator: smuggle-sni requires a normal top-level next node");
            tunnelDestroy(t);
            return NULL;
        }

        if (! getStringFromJsonObject(&real_sni_upstream_node_name, settings, "real-sni-upstream-node"))
        {
            LOGF("IpManipulator: smuggle-sni requires \"real-sni-upstream-node\"");
            tunnelDestroy(t);
            return NULL;
        }

        node_t *real_sni_upstream_node =
            nodemanagerGetConfigNodeByName(node->node_manager_config, real_sni_upstream_node_name);

        if (real_sni_upstream_node == NULL)
        {
            LOGF("IpManipulator: real-sni-upstream-node \"%s\" not found", real_sni_upstream_node_name);
            memoryFree(real_sni_upstream_node_name);
            tunnelDestroy(t);
            return NULL;
        }

        if (real_sni_upstream_node == node)
        {
            LOGF("IpManipulator: real-sni-upstream-node must not point back to IpManipulator itself");
            memoryFree(real_sni_upstream_node_name);
            tunnelDestroy(t);
            return NULL;
        }

        memoryFree(real_sni_upstream_node_name);

        if (getIntFromJsonObject(&smuggle_sni_delay_ms, settings, "smuggle-sni-delay-ms"))
        {
            if (smuggle_sni_delay_ms < 0)
            {
                LOGF("IpManipulator: smuggle-sni field \"smuggle-sni-delay-ms\" must be zero or greater");
                tunnelDestroy(t);
                return NULL;
            }
        }

        state->trick_smuggle_sni_value_len  = (uint16_t) smuggle_sni_len;
        state->trick_smuggle_sni_delay_ms   = (uint32_t) smuggle_sni_delay_ms;
        state->trick_real_sni_upstream_node = real_sni_upstream_node;
        state->trick_smuggle_sni            = true;
    }

    bool has_overlap_sni = getStringFromJsonObject(&state->trick_overlap_sni_value, settings, "overlap-sni");
    if (has_overlap_sni)
    {
        int    overlap_sni_delay_ms        = 0;
        int    overlap_sni_hold_timeout_ms = 50;
        int    overlap_sni_syn_ttl         = -1;
        size_t overlap_sni_len             = stringLength(state->trick_overlap_sni_value);

        if (overlap_sni_len == 0)
        {
            LOGF("IpManipulator: overlap-sni field \"overlap-sni\" must not be empty");
            tunnelDestroy(t);
            return NULL;
        }

        if (overlap_sni_len > UINT16_MAX)
        {
            LOGF("IpManipulator: overlap-sni field \"overlap-sni\" must fit in 16-bit TLS length fields");
            tunnelDestroy(t);
            return NULL;
        }

        if (getIntFromJsonObject(&overlap_sni_hold_timeout_ms, settings, "overlap-sni-hold-timeout-ms") &&
            overlap_sni_hold_timeout_ms <= 0)
        {
            LOGF("IpManipulator: overlap-sni field \"overlap-sni-hold-timeout-ms\" must be greater than zero");
            tunnelDestroy(t);
            return NULL;
        }

        if (! nodeHasNext(node))
        {
            LOGF("IpManipulator: overlap-sni requires a normal top-level next node");
            tunnelDestroy(t);
            return NULL;
        }

        if (getIntFromJsonObject(&overlap_sni_delay_ms, settings, "overlap-sni-delay-ms"))
        {
            if (overlap_sni_delay_ms < 0)
            {
                LOGF("IpManipulator: overlap-sni field \"overlap-sni-delay-ms\" must be zero or greater");
                tunnelDestroy(t);
                return NULL;
            }
        }

        if (getIntFromJsonObject(&overlap_sni_syn_ttl, settings, "overlap-sni-syn-ttl"))
        {
            if (overlap_sni_syn_ttl < 0 || overlap_sni_syn_ttl > UINT8_MAX)
            {
                LOGF("IpManipulator: overlap-sni field \"overlap-sni-syn-ttl\" must be between 0 and 255");
                tunnelDestroy(t);
                return NULL;
            }
        }

        state->trick_overlap_sni_value_len       = (uint16_t) overlap_sni_len;
        state->trick_overlap_sni_delay_ms        = (uint32_t) overlap_sni_delay_ms;
        state->trick_overlap_sni_hold_timeout_ms = (uint32_t) overlap_sni_hold_timeout_ms;
        state->trick_overlap_sni_syn_ttl         = overlap_sni_syn_ttl;
        state->trick_overlap_sni                 = true;
    }

    bool has_synfin_sni = getStringFromJsonObject(&state->trick_synfin_sni_value, settings, "synfin-sni");
    if (has_synfin_sni)
    {
        size_t synfin_sni_len                  = stringLength(state->trick_synfin_sni_value);
        int    synfin_sni_additional_range_min = 0;
        int    synfin_sni_additional_range_max = 0;
        int    synfin_sni_hold_timeout_ms      = 50;
        bool   has_synfin_sni_additional_range_min =
            getIntFromJsonObject(&synfin_sni_additional_range_min, settings, "synfin-sni-additional-range-min");
        bool has_synfin_sni_additional_range_max =
            getIntFromJsonObject(&synfin_sni_additional_range_max, settings, "synfin-sni-additional-range-max");

        if (synfin_sni_len == 0)
        {
            LOGF("IpManipulator: synfin-sni field \"synfin-sni\" must not be empty");
            tunnelDestroy(t);
            return NULL;
        }

        if (synfin_sni_len > UINT16_MAX)
        {
            LOGF("IpManipulator: synfin-sni field \"synfin-sni\" must fit in 16-bit TLS length fields");
            tunnelDestroy(t);
            return NULL;
        }

        if (getIntFromJsonObject(&synfin_sni_hold_timeout_ms, settings, "synfin-sni-hold-timeout-ms") &&
            synfin_sni_hold_timeout_ms <= 0)
        {
            LOGF("IpManipulator: synfin-sni field \"synfin-sni-hold-timeout-ms\" must be greater than zero");
            tunnelDestroy(t);
            return NULL;
        }

        if (! nodeHasNext(node))
        {
            LOGF("IpManipulator: synfin-sni requires a normal top-level next node");
            tunnelDestroy(t);
            return NULL;
        }

        if (has_synfin_sni_additional_range_min && ! has_synfin_sni_additional_range_max)
        {
            synfin_sni_additional_range_max = synfin_sni_additional_range_min;
        }

        if (synfin_sni_additional_range_min < 0 || synfin_sni_additional_range_max < 0 ||
            synfin_sni_additional_range_min > UINT16_MAX || synfin_sni_additional_range_max > UINT16_MAX)
        {
            LOGF("IpManipulator: synfin-sni additional range fields must be between 0 and %u", UINT16_MAX);
            tunnelDestroy(t);
            return NULL;
        }

        if (synfin_sni_additional_range_min > synfin_sni_additional_range_max)
        {
            LOGF("IpManipulator: synfin-sni field \"synfin-sni-additional-range-min\" must be <= "
                 "\"synfin-sni-additional-range-max\"");
            tunnelDestroy(t);
            return NULL;
        }

        if (getIntFromJsonObject(&state->trick_synfin_sni_syn_ttl, settings, "synfin-sni-syn-ttl"))
        {
            if (state->trick_synfin_sni_syn_ttl < 0 || state->trick_synfin_sni_syn_ttl > UINT8_MAX)
            {
                LOGF("IpManipulator: synfin-sni field \"synfin-sni-syn-ttl\" must be between 0 and 255");
                tunnelDestroy(t);
                return NULL;
            }
        }

        if (getIntFromJsonObject(&state->trick_synfin_sni_fin_ttl, settings, "synfin-sni-fin-ttl"))
        {
            if (state->trick_synfin_sni_fin_ttl < 0 || state->trick_synfin_sni_fin_ttl > UINT8_MAX)
            {
                LOGF("IpManipulator: synfin-sni field \"synfin-sni-fin-ttl\" must be between 0 and 255");
                tunnelDestroy(t);
                return NULL;
            }
        }

        if (getIntFromJsonObject(&state->trick_synfin_sni_fake_ttl, settings, "synfin-sni-fake-ttl"))
        {
            if (state->trick_synfin_sni_fake_ttl < 0 || state->trick_synfin_sni_fake_ttl > UINT8_MAX)
            {
                LOGF("IpManipulator: synfin-sni field \"synfin-sni-fake-ttl\" must be between 0 and 255");
                tunnelDestroy(t);
                return NULL;
            }
        }

        getBoolFromJsonObject(&state->trick_synfin_sni_random_syn_checksum, settings, "synfin-sni-random-syn-checksum");
        getBoolFromJsonObject(&state->trick_synfin_sni_random_fin_checksum, settings, "synfin-sni-random-fin-checksum");
        getBoolFromJsonObject(&state->trick_synfin_sni_random_syn_sequence, settings, "synfin-sni-random-syn-sequence");
        getBoolFromJsonObject(&state->trick_synfin_sni_random_fin_sequence, settings, "synfin-sni-random-fin-sequence");
        getBoolFromJsonObject(&state->trick_synfin_sni_use_rst, settings, "synfin-sni-use-rst");

        state->trick_synfin_sni_value_len            = (uint16_t) synfin_sni_len;
        state->trick_synfin_sni_hold_timeout_ms      = (uint32_t) synfin_sni_hold_timeout_ms;
        state->trick_synfin_sni_additional_range_min = (uint16_t) synfin_sni_additional_range_min;
        state->trick_synfin_sni_additional_range_max = (uint16_t) synfin_sni_additional_range_max;
        state->trick_synfin_sni                      = true;

        if (state->trick_synfin_sni_fake_ttl < 0 &&
            (state->trick_synfin_sni_syn_ttl == 0 || state->trick_synfin_sni_fin_ttl == 0))
        {
            LOGW("IpManipulator: synfin-sni TTL override 0 on SYN/FIN only affects those control packets; "
                 "the crafted fake TLS packets still keep the original TTL unless \"synfin-sni-fake-ttl\" is set");
        }
    }

    bool has_ech_sni = getStringFromJsonObject(&state->trick_ech_sni_value, settings, "ech-sni-trick");
    if (has_ech_sni)
    {
        int    shard1_delay_ms = 0;
        int    shard2_delay_ms = 0;
        size_t ech_sni_len     = stringLength(state->trick_ech_sni_value);

        if (ech_sni_len == 0)
        {
            LOGF("IpManipulator: ech-sni-trick field \"ech-sni-trick\" must not be empty");
            tunnelDestroy(t);
            return NULL;
        }

        if (ech_sni_len > kIpManipulatorMaxTlsHostNameLen)
        {
            LOGF("IpManipulator: ech-sni-trick field \"ech-sni-trick\" must not be longer than %d bytes",
                 kIpManipulatorMaxTlsHostNameLen);
            tunnelDestroy(t);
            return NULL;
        }

        if (! nodeHasNext(node))
        {
            LOGF("IpManipulator: ech-sni-trick requires a normal top-level next node");
            tunnelDestroy(t);
            return NULL;
        }

        if (getIntFromJsonObject(&shard1_delay_ms, settings, "data-shard-1-delay"))
        {
            if (shard1_delay_ms < 0)
            {
                LOGF("IpManipulator: ech-sni-trick field \"data-shard-1-delay\" must be zero or greater");
                tunnelDestroy(t);
                return NULL;
            }
        }

        if (getIntFromJsonObject(&shard2_delay_ms, settings, "data-shard-2-delay"))
        {
            if (shard2_delay_ms < 0)
            {
                LOGF("IpManipulator: ech-sni-trick field \"data-shard-2-delay\" must be zero or greater");
                tunnelDestroy(t);
                return NULL;
            }
        }

        if ((uint64_t) shard1_delay_ms + (uint64_t) shard2_delay_ms > UINT32_MAX)
        {
            LOGF("IpManipulator: ech-sni-trick combined shard delay exceeds supported range");
            tunnelDestroy(t);
            return NULL;
        }

        state->trick_ech_sni_value_len       = (uint16_t) ech_sni_len;
        state->trick_ech_sni_shard1_delay_ms = (uint32_t) shard1_delay_ms;
        state->trick_ech_sni_shard2_delay_ms = (uint32_t) shard2_delay_ms;
        state->trick_ech_sni                 = true;
    }

    /*
     * The pairwise stateful-SNI checks that used to live here are now part of
     * ipmanipulatorValidateTrickCompatibility(), reported by
     * reportTrickCompatibility() below.
     */

    bool smuggle_fin_enabled = false;
    getBoolFromJsonObject(&smuggle_fin_enabled, settings, "smuggle-fin");
    if (smuggle_fin_enabled)
    {
        int   smuggle_fin_delay_ms         = 0;
        int   smuggle_fin_pause_timeout_ms = 1000;
        char *real_fin_upstream_node_name  = NULL;

        if (! nodeHasNext(node))
        {
            LOGF("IpManipulator: smuggle-fin requires a normal top-level next node");
            tunnelDestroy(t);
            return NULL;
        }

        if (! getStringFromJsonObject(&real_fin_upstream_node_name, settings, "real-fin-upstream-node"))
        {
            LOGF("IpManipulator: smuggle-fin requires \"real-fin-upstream-node\"");
            tunnelDestroy(t);
            return NULL;
        }

        node_t *real_fin_upstream_node =
            nodemanagerGetConfigNodeByName(node->node_manager_config, real_fin_upstream_node_name);

        if (real_fin_upstream_node == NULL)
        {
            LOGF("IpManipulator: real-fin-upstream-node \"%s\" not found", real_fin_upstream_node_name);
            memoryFree(real_fin_upstream_node_name);
            tunnelDestroy(t);
            return NULL;
        }

        if (real_fin_upstream_node == node)
        {
            LOGF("IpManipulator: real-fin-upstream-node must not point back to IpManipulator itself");
            memoryFree(real_fin_upstream_node_name);
            tunnelDestroy(t);
            return NULL;
        }

        memoryFree(real_fin_upstream_node_name);

        if (getIntFromJsonObject(&smuggle_fin_delay_ms, settings, "fin-sni-delay-ms"))
        {
            if (smuggle_fin_delay_ms < 0)
            {
                LOGF("IpManipulator: smuggle-fin field \"fin-sni-delay-ms\" must be zero or greater");
                tunnelDestroy(t);
                return NULL;
            }
        }

        if (getIntFromJsonObject(&smuggle_fin_pause_timeout_ms, settings, "fin-pause-timeout-ms"))
        {
            if (smuggle_fin_pause_timeout_ms <= 0)
            {
                LOGF("IpManipulator: smuggle-fin field \"fin-pause-timeout-ms\" must be greater than zero");
                tunnelDestroy(t);
                return NULL;
            }
        }

        state->trick_real_fin_upstream_node       = real_fin_upstream_node;
        state->trick_smuggle_fin_delay_ms         = (uint32_t) smuggle_fin_delay_ms;
        state->trick_smuggle_fin_pause_timeout_ms = (uint32_t) smuggle_fin_pause_timeout_ms;
        state->trick_smuggle_fin                  = true;
    }

    bool tcp_parse_ok = true;
    tcp_parse_ok &= parseTcpBitActionField(&state->up_tcp_bit_cwr_action, settings, "up-tcp-bit-cwr");
    tcp_parse_ok &= parseTcpBitActionField(&state->up_tcp_bit_ece_action, settings, "up-tcp-bit-ece");
    tcp_parse_ok &= parseTcpBitActionField(&state->up_tcp_bit_urg_action, settings, "up-tcp-bit-urg");
    tcp_parse_ok &= parseTcpBitActionField(&state->up_tcp_bit_ack_action, settings, "up-tcp-bit-ack");
    tcp_parse_ok &= parseTcpBitActionField(&state->up_tcp_bit_psh_action, settings, "up-tcp-bit-psh");
    tcp_parse_ok &= parseTcpBitActionField(&state->up_tcp_bit_rst_action, settings, "up-tcp-bit-rst");
    tcp_parse_ok &= parseTcpBitActionField(&state->up_tcp_bit_syn_action, settings, "up-tcp-bit-syn");
    tcp_parse_ok &= parseTcpBitActionField(&state->up_tcp_bit_fin_action, settings, "up-tcp-bit-fin");

    tcp_parse_ok &= parseTcpBitActionField(&state->down_tcp_bit_cwr_action, settings, "dw-tcp-bit-cwr");
    tcp_parse_ok &= parseTcpBitActionField(&state->down_tcp_bit_ece_action, settings, "dw-tcp-bit-ece");
    tcp_parse_ok &= parseTcpBitActionField(&state->down_tcp_bit_urg_action, settings, "dw-tcp-bit-urg");
    tcp_parse_ok &= parseTcpBitActionField(&state->down_tcp_bit_ack_action, settings, "dw-tcp-bit-ack");
    tcp_parse_ok &= parseTcpBitActionField(&state->down_tcp_bit_psh_action, settings, "dw-tcp-bit-psh");
    tcp_parse_ok &= parseTcpBitActionField(&state->down_tcp_bit_rst_action, settings, "dw-tcp-bit-rst");
    tcp_parse_ok &= parseTcpBitActionField(&state->down_tcp_bit_syn_action, settings, "dw-tcp-bit-syn");
    tcp_parse_ok &= parseTcpBitActionField(&state->down_tcp_bit_fin_action, settings, "dw-tcp-bit-fin");

    if (! tcp_parse_ok)
    {
        tunnelDestroy(t);
        return NULL;
    }

    state->trick_tcp_bit_changes =
        (state->down_tcp_bit_cwr_action != kDvsNoAction || state->down_tcp_bit_ece_action != kDvsNoAction ||
         state->down_tcp_bit_urg_action != kDvsNoAction || state->down_tcp_bit_ack_action != kDvsNoAction ||
         state->down_tcp_bit_psh_action != kDvsNoAction || state->down_tcp_bit_rst_action != kDvsNoAction ||
         state->down_tcp_bit_syn_action != kDvsNoAction || state->down_tcp_bit_fin_action != kDvsNoAction ||
         state->up_tcp_bit_cwr_action != kDvsNoAction || state->up_tcp_bit_ece_action != kDvsNoAction ||
         state->up_tcp_bit_urg_action != kDvsNoAction || state->up_tcp_bit_ack_action != kDvsNoAction ||
         state->up_tcp_bit_psh_action != kDvsNoAction || state->up_tcp_bit_rst_action != kDvsNoAction ||
         state->up_tcp_bit_syn_action != kDvsNoAction || state->up_tcp_bit_fin_action != kDvsNoAction);

    if (! reportTrickCompatibility(state))
    {
        tunnelDestroy(t);
        return NULL;
    }

    if (! (state->trick_proto_swap || state->trick_sni_blender || state->trick_first_sni || state->trick_smuggle_sni ||
           state->trick_overlap_sni || state->trick_synfin_sni || state->trick_ech_sni || state->trick_smuggle_fin ||
           state->trick_tcp_bit_changes || state->trick_packet_duplicate || state->trick_preserve_tcp_bitflags ||
           state->trick_source_port_ghost || state->trick_dest_port_ghost))
    {
        LOGF("IpManipulator: no tricks are enabled, nothing to do");
        tunnelDestroy(t);
        return NULL;
    }

    if (! createConfiguredTlsClient(t, node))
    {
        ipmanipulatorDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (state->trick_first_sni || state->trick_smuggle_sni || state->trick_ech_sni)
    {
        if (UNLIKELY(! mutexTryInit(&state->tls_capture_mutex)))
        {
            LOGF("IpManipulator: failed to initialize TLS ClientHello capture mutex");
            ipmanipulatorDestroy(t, wwLifecycleStartupRollback());
            return NULL;
        }
        state->tls_capture_slots_count = (uint32_t) getTotalWorkersCount() * kIpManipulatorTlsCaptureSlotsPerWorker;
        state->tls_capture_slots =
            memoryAllocateZero(sizeof(*state->tls_capture_slots) * state->tls_capture_slots_count);
        state->tls_prestart_slots_count = state->tls_capture_slots_count;
        state->tls_prestart_slots =
            memoryAllocateZero(sizeof(*state->tls_prestart_slots) * state->tls_prestart_slots_count);

        if (state->tls_capture_slots == NULL || state->tls_prestart_slots == NULL)
        {
            memoryFree(state->tls_capture_slots);
            memoryFree(state->tls_prestart_slots);
            state->tls_capture_slots        = NULL;
            state->tls_prestart_slots       = NULL;
            state->tls_capture_slots_count  = 0;
            state->tls_prestart_slots_count = 0;
            mutexDestroy(&state->tls_capture_mutex);

            LOGF("IpManipulator: failed to allocate the TLS ClientHello capture slots");
            ipmanipulatorDestroy(t, wwLifecycleStartupRollback());
            return NULL;
        }
    }

    if (! initializeStatefulTrickTables(t))
    {
        ipmanipulatorDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    return t;
}
