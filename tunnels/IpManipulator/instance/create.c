#include "structure.h"

#include "loggers/network_logger.h"

#include "tricks/firstsni/trick.h"
#include "tricks/protoswap/trick.h"
#include "tricks/smugglesni/trick.h"
#include "tricks/sniblender/trick.h"
#include "tricks/tcpbitchange/trick.h"

static bool parseTcpBitActionField(enum tcp_bit_action_dynamic_value *dest, const cJSON *settings, const char *key)
{
    dynamic_value_t action = parseDynamicStrValueFromJsonObject(
        settings, key, 11, "off", "on", "toggle", "packet->cwr", "packet->ece", "packet->urg", "packet->ack",
        "packet->psh", "packet->rst", "packet->syn", "packet->fin");

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

static bool validateProtocolSwapNumber(const char *key, int protocol_number)
{
    if (protocol_number < 0 || protocol_number > UINT8_MAX)
    {
        LOGF("IpManipulator: settings->%s must be between 0 and 255", key);
        return false;
    }

    return true;
}

tunnel_t *ipmanipulatorCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(ipmanipulator_tstate_t), 0);

    t->fnInitU    = &ipmanipulatorUpStreamInit;
    t->fnPayloadU = &ipmanipulatorUpStreamPayload;
    t->fnPayloadD = &ipmanipulatorDownStreamPayload;
    t->onChain    = &ipmanipulatorOnChain;
    t->onPrepare  = &ipmanipulatorOnPrepair;
    t->onStart    = &ipmanipulatorOnStart;
    t->onDestroy  = &ipmanipulatorDestroy;

    ipmanipulator_tstate_t *state    = tunnelGetState(t);
    const cJSON            *settings = node->node_settings_json;

    state->trick_proto_swap_tcp_number      = -1;
    state->trick_proto_swap_tcp_number_2    = -1;
    state->trick_proto_swap_udp_number      = -1;
    state->trick_proto_swap_tcp_toggle_up   = 0;
    state->trick_proto_swap_tcp_toggle_down = 0;
    state->trick_overlap_sni_syn_ttl        = -1;
    state->trick_synfin_sni_syn_ttl              = -1;
    state->trick_synfin_sni_fin_ttl              = -1;
    state->trick_synfin_sni_fake_ttl             = -1;
    state->trick_synfin_sni_additional_range_min = 0;
    state->trick_synfin_sni_additional_range_max = 0;
    state->trick_ech_sni_shard1_delay_ms         = 0;
    state->trick_ech_sni_shard2_delay_ms         = 0;

    bool has_proto_swap_legacy = false;
    bool has_proto_swap_tcp    = false;
    bool has_proto_swap_udp    = false;
    bool has_proto_swap_tcp_2  = false;
    has_proto_swap_legacy = getIntFromJsonObject(&state->trick_proto_swap_tcp_number, settings, "protoswap");
    has_proto_swap_tcp    = getIntFromJsonObject(&state->trick_proto_swap_tcp_number, settings, "protoswap-tcp");
    has_proto_swap_udp    = getIntFromJsonObject(&state->trick_proto_swap_udp_number, settings, "protoswap-udp");
    has_proto_swap_tcp_2 =
        getIntFromJsonObject(&state->trick_proto_swap_tcp_number_2, settings, "protoswap-tcp-2");

    const char *proto_swap_tcp_key = has_proto_swap_tcp ? "protoswap-tcp" : "protoswap";

    if (((has_proto_swap_legacy || has_proto_swap_tcp) &&
         ! validateProtocolSwapNumber(proto_swap_tcp_key, state->trick_proto_swap_tcp_number)) ||
        (has_proto_swap_udp && ! validateProtocolSwapNumber("protoswap-udp", state->trick_proto_swap_udp_number)) ||
        (has_proto_swap_tcp_2 &&
         ! validateProtocolSwapNumber("protoswap-tcp-2", state->trick_proto_swap_tcp_number_2)))
    {
        tunnelDestroy(t);
        return NULL;
    }

    state->trick_proto_swap = has_proto_swap_legacy || has_proto_swap_tcp || has_proto_swap_udp;

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

        if (state->trick_sni_blender_packets_count <= 0)
        {
            LOGF("IpManipulator: sni-blender-packets must be greater than zero");
            tunnelDestroy(t);
            return NULL;
        }

        if (state->trick_sni_blender_packets_count > kSniBlenderTrickMaxPacketsCount)
        {
            LOGF("IpManipulator: sni-blender-packets cannot be more than %d", kSniBlenderTrickMaxPacketsCount);
            tunnelDestroy(t);
            return NULL;
        }

        state->trick_sni_blender = true;
    }

    if (getIntFromJsonObject(&state->trick_packet_duplicate_count, settings, "packet-duplicate"))
    {
        if (state->trick_packet_duplicate_count <= 0)
        {
            LOGF("IpManipulator: packet-duplicate must be greater than zero");
            tunnelDestroy(t);
            return NULL;
        }

        state->trick_packet_duplicate = true;
    }

    bool bit_transport_enabled = false;
    getBoolFromJsonObject(&bit_transport_enabled, settings, "bit-transport");
    state->trick_bit_transport = bit_transport_enabled;

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
            if (first_sni_count <= 0)
            {
                LOGF("IpManipulator: first-sni field \"first-sni-count\" must be greater than zero");
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
        int    smuggle_sni_delay_ms         = 0;
        size_t smuggle_sni_len              = stringLength(state->trick_smuggle_sni_value);

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

        node_t *real_sni_upstream_node = nodemanagerGetConfigNodeByName(node->node_manager_config, real_sni_upstream_node_name);

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

        char* name_of_new_tlsclient_node = memoryAllocate(128);
        stringNPrintf(name_of_new_tlsclient_node, 128, "ipm_tlsc_%s", state->trick_smuggle_sni_value);

        char* json_string_of_tls_client = memoryAllocate(256 + smuggle_sni_len);
        static const char* tls_client_json = "{\"name\":\"%s\",\"type\":\"TlsClient\",\"settings\":{\"sni\":\"%s\",\"x25519mlkem768\":false}}";
        stringNPrintf(json_string_of_tls_client, 256 + smuggle_sni_len, tls_client_json, name_of_new_tlsclient_node, state->trick_smuggle_sni_value);
        cJSON *json_of_tls_client = cJSON_ParseWithLength(json_string_of_tls_client, stringLength(json_string_of_tls_client));
        nodemanagerCreateNodeInstance(node->node_manager_config, json_of_tls_client);


        state->trick_real_sni_tls_client_node = nodemanagerGetConfigNodeByName(node->node_manager_config, name_of_new_tlsclient_node);
        state->trick_smuggle_sni_value_len     = (uint16_t) smuggle_sni_len;
        state->trick_smuggle_sni_delay_ms      = (uint32_t) smuggle_sni_delay_ms;
        state->trick_real_sni_upstream_node   = real_sni_upstream_node;
        state->trick_smuggle_sni              = true;

        state->trick_real_sni_tls_client_node->flags |= kNodeFlagNoChain;

        memoryFree(name_of_new_tlsclient_node);
        memoryFree(json_string_of_tls_client);
    }

    bool has_overlap_sni = getStringFromJsonObject(&state->trick_overlap_sni_value, settings, "overlap-sni");
    if (has_overlap_sni)
    {
        char  *server_hello_upstream_node_name   = NULL;
        int    overlap_sni_delay_ms              = 0;
        int    overlap_sni_syn_ttl               = -1;
        size_t overlap_sni_len                   = stringLength(state->trick_overlap_sni_value);

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

        if (! nodeHasNext(node))
        {
            LOGF("IpManipulator: overlap-sni requires a normal top-level next node");
            tunnelDestroy(t);
            return NULL;
        }

        if (! getStringFromJsonObject(&server_hello_upstream_node_name, settings, "crafted-server-hello-upstream-node"))
        {
            LOGF("IpManipulator: overlap-sni requires \"crafted-server-hello-upstream-node\"");
            tunnelDestroy(t);
            return NULL;
        }

        node_t *server_hello_upstream_node =
            nodemanagerGetConfigNodeByName(node->node_manager_config, server_hello_upstream_node_name);

        if (server_hello_upstream_node == NULL)
        {
            LOGF("IpManipulator: crafted-server-hello-upstream-node \"%s\" not found", server_hello_upstream_node_name);
            memoryFree(server_hello_upstream_node_name);
            tunnelDestroy(t);
            return NULL;
        }

        if (server_hello_upstream_node == node)
        {
            LOGF("IpManipulator: crafted-server-hello-upstream-node must not point back to IpManipulator itself");
            memoryFree(server_hello_upstream_node_name);
            tunnelDestroy(t);
            return NULL;
        }

        memoryFree(server_hello_upstream_node_name);

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

        size_t name_len = 32 + overlap_sni_len;
        char  *name_of_new_tlsclient_node = memoryAllocate(name_len);
        stringNPrintf(name_of_new_tlsclient_node,
                      name_len,
                      "ipm_tlsc_overlap_%s",
                      state->trick_overlap_sni_value);

        char              *json_string_of_tls_client = memoryAllocate(256 + overlap_sni_len);
        static const char *tls_client_json =
            "{\"name\":\"%s\",\"type\":\"TlsClient\",\"settings\":{\"sni\":\"%s\",\"x25519mlkem768\":false}}";
        stringNPrintf(json_string_of_tls_client,
                      256 + overlap_sni_len,
                      tls_client_json,
                      name_of_new_tlsclient_node,
                      state->trick_overlap_sni_value);
        cJSON *json_of_tls_client = cJSON_ParseWithLength(json_string_of_tls_client, stringLength(json_string_of_tls_client));
        nodemanagerCreateNodeInstance(node->node_manager_config, json_of_tls_client);

        state->trick_overlap_sni_tls_client_node =
            nodemanagerGetConfigNodeByName(node->node_manager_config, name_of_new_tlsclient_node);

        if (state->trick_overlap_sni_tls_client_node == NULL)
        {
            LOGF("IpManipulator: failed to create internal overlap-sni TlsClient helper node");
            memoryFree(name_of_new_tlsclient_node);
            memoryFree(json_string_of_tls_client);
            tunnelDestroy(t);
            return NULL;
        }

        state->trick_overlap_sni_value_len = (uint16_t) overlap_sni_len;
        state->trick_overlap_sni_delay_ms  = (uint32_t) overlap_sni_delay_ms;
        state->trick_overlap_sni_syn_ttl   = overlap_sni_syn_ttl;
        state->trick_overlap_sni_server_hello_upstream_node = server_hello_upstream_node;
        state->trick_overlap_sni           = true;

        state->trick_overlap_sni_tls_client_node->flags |= kNodeFlagNoChain;

        memoryFree(name_of_new_tlsclient_node);
        memoryFree(json_string_of_tls_client);
    }

    bool has_synfin_sni = getStringFromJsonObject(&state->trick_synfin_sni_value, settings, "synfin-sni");
    if (has_synfin_sni)
    {
        size_t synfin_sni_len = stringLength(state->trick_synfin_sni_value);
        int    synfin_sni_additional_range_min = 0;
        int    synfin_sni_additional_range_max = 0;
        bool   has_synfin_sni_additional_range_min =
            getIntFromJsonObject(
                &synfin_sni_additional_range_min, settings, "synfin-sni-additional-range-min");
        bool has_synfin_sni_additional_range_max =
            getIntFromJsonObject(
                &synfin_sni_additional_range_max, settings, "synfin-sni-additional-range-max");

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

        getBoolFromJsonObject(
            &state->trick_synfin_sni_random_syn_checksum, settings, "synfin-sni-random-syn-checksum");
        getBoolFromJsonObject(
            &state->trick_synfin_sni_random_fin_checksum, settings, "synfin-sni-random-fin-checksum");
        getBoolFromJsonObject(
            &state->trick_synfin_sni_random_syn_sequence, settings, "synfin-sni-random-syn-sequence");
        getBoolFromJsonObject(
            &state->trick_synfin_sni_random_fin_sequence, settings, "synfin-sni-random-fin-sequence");
        getBoolFromJsonObject(&state->trick_synfin_sni_use_rst, settings, "synfin-sni-use-rst");

        size_t name_len = 32 + synfin_sni_len;
        char  *name_of_new_tlsclient_node = memoryAllocate(name_len);
        stringNPrintf(name_of_new_tlsclient_node,
                      name_len,
                      "ipm_tlsc_synfin_%s",
                      state->trick_synfin_sni_value);

        char              *json_string_of_tls_client = memoryAllocate(256 + synfin_sni_len);
        static const char *tls_client_json =
            "{\"name\":\"%s\",\"type\":\"TlsClient\",\"settings\":{\"sni\":\"%s\",\"x25519mlkem768\":false}}";
        stringNPrintf(json_string_of_tls_client,
                      256 + synfin_sni_len,
                      tls_client_json,
                      name_of_new_tlsclient_node,
                      state->trick_synfin_sni_value);
        cJSON *json_of_tls_client =
            cJSON_ParseWithLength(json_string_of_tls_client, stringLength(json_string_of_tls_client));
        nodemanagerCreateNodeInstance(node->node_manager_config, json_of_tls_client);

        state->trick_synfin_sni_tls_client_node =
            nodemanagerGetConfigNodeByName(node->node_manager_config, name_of_new_tlsclient_node);

        if (state->trick_synfin_sni_tls_client_node == NULL)
        {
            LOGF("IpManipulator: failed to create internal synfin-sni TlsClient helper node");
            memoryFree(name_of_new_tlsclient_node);
            memoryFree(json_string_of_tls_client);
            tunnelDestroy(t);
            return NULL;
        }

        state->trick_synfin_sni_value_len            = (uint16_t) synfin_sni_len;
        state->trick_synfin_sni_additional_range_min = (uint16_t) synfin_sni_additional_range_min;
        state->trick_synfin_sni_additional_range_max = (uint16_t) synfin_sni_additional_range_max;
        state->trick_synfin_sni                      = true;

        if (state->trick_synfin_sni_fake_ttl < 0 &&
            (state->trick_synfin_sni_syn_ttl == 0 || state->trick_synfin_sni_fin_ttl == 0))
        {
            LOGW("IpManipulator: synfin-sni TTL override 0 on SYN/FIN only affects those control packets; "
                 "the crafted fake TLS packets still keep the original TTL unless \"synfin-sni-fake-ttl\" is set");
        }

        state->trick_synfin_sni_tls_client_node->flags |= kNodeFlagNoChain;

        memoryFree(name_of_new_tlsclient_node);
        memoryFree(json_string_of_tls_client);
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

        if (ech_sni_len > UINT16_MAX)
        {
            LOGF("IpManipulator: ech-sni-trick field \"ech-sni-trick\" must fit in 16-bit TLS length fields");
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

        state->trick_ech_sni_value_len        = (uint16_t) ech_sni_len;
        state->trick_ech_sni_shard1_delay_ms  = (uint32_t) shard1_delay_ms;
        state->trick_ech_sni_shard2_delay_ms  = (uint32_t) shard2_delay_ms;
        state->trick_ech_sni                  = true;
    }

    if (state->trick_smuggle_sni && state->trick_overlap_sni)
    {
        LOGF("IpManipulator: smuggle-sni and overlap-sni cannot be enabled at the same time");
        tunnelDestroy(t);
        return NULL;
    }

    if (state->trick_smuggle_sni && state->trick_synfin_sni)
    {
        LOGF("IpManipulator: smuggle-sni and synfin-sni cannot be enabled at the same time");
        tunnelDestroy(t);
        return NULL;
    }

    if (state->trick_overlap_sni && state->trick_synfin_sni)
    {
        LOGF("IpManipulator: overlap-sni and synfin-sni cannot be enabled at the same time");
        tunnelDestroy(t);
        return NULL;
    }

    if (state->trick_ech_sni && state->trick_smuggle_sni)
    {
        LOGF("IpManipulator: ech-sni-trick and smuggle-sni cannot be enabled at the same time");
        tunnelDestroy(t);
        return NULL;
    }

    if (state->trick_ech_sni && state->trick_overlap_sni)
    {
        LOGF("IpManipulator: ech-sni-trick and overlap-sni cannot be enabled at the same time");
        tunnelDestroy(t);
        return NULL;
    }

    if (state->trick_ech_sni && state->trick_synfin_sni)
    {
        LOGF("IpManipulator: ech-sni-trick and synfin-sni cannot be enabled at the same time");
        tunnelDestroy(t);
        return NULL;
    }

    bool smuggle_fin_enabled = false;
    getBoolFromJsonObject(&smuggle_fin_enabled, settings, "smuggle-fin");
    if (smuggle_fin_enabled)
    {
        int   smuggle_fin_delay_ms      = 0;
        char *real_fin_upstream_node_name = NULL;

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

        state->trick_real_fin_upstream_node = real_fin_upstream_node;
        state->trick_smuggle_fin_delay_ms   = (uint32_t) smuggle_fin_delay_ms;
        state->trick_smuggle_fin            = true;
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

    if (! (state->trick_proto_swap || state->trick_sni_blender || state->trick_first_sni || state->trick_smuggle_sni ||
           state->trick_overlap_sni || state->trick_synfin_sni || state->trick_ech_sni || state->trick_smuggle_fin ||
           state->trick_tcp_bit_changes ||
           state->trick_packet_duplicate || state->trick_bit_transport || state->trick_source_port_ghost ||
           state->trick_dest_port_ghost))
    {
        LOGF("IpManipulator: no tricks are enabled, nothing to do");
        tunnelDestroy(t);
        return NULL;
    }

    if (state->trick_first_sni)
    {
        mutexInit(&state->tls_capture_mutex);
        state->tls_capture_slots_count = (uint32_t) getTotalWorkersCount() * kIpManipulatorTlsCaptureSlotsPerWorker;
        state->tls_capture_slots = memoryAllocateZero(sizeof(*state->tls_capture_slots) * state->tls_capture_slots_count);
        state->tls_prestart_slots_count = state->tls_capture_slots_count;
        state->tls_prestart_slots =
            memoryAllocateZero(sizeof(*state->tls_prestart_slots) * state->tls_prestart_slots_count);

        uint32_t initial_flows = max(kIpManipulatorSmuggleInitialFlows, (uint32_t) getTotalWorkersCount() * 8U);

        mutexInit(&state->first_sni_flows_mutex);
        state->first_sni_flows_capacity = initial_flows;
        state->first_sni_flows          = memoryAllocateZero(sizeof(*state->first_sni_flows) * initial_flows);
    }

    if (state->trick_smuggle_sni)
    {
        uint32_t initial_flows = max(kIpManipulatorSmuggleInitialFlows, (uint32_t) getTotalWorkersCount() * 8U);

        mutexInit(&state->smuggle_flows_mutex);
        state->smuggle_flows_capacity = initial_flows;
        state->smuggle_flows          = memoryAllocateZero(sizeof(*state->smuggle_flows) * initial_flows);
    }

    if (state->trick_overlap_sni)
    {
        uint32_t initial_flows = max(kIpManipulatorSmuggleInitialFlows, (uint32_t) getTotalWorkersCount() * 8U);

        mutexInit(&state->overlap_flows_mutex);
        state->overlap_flows_capacity = initial_flows;
        state->overlap_flows          = memoryAllocateZero(sizeof(*state->overlap_flows) * initial_flows);
    }

    if (state->trick_synfin_sni)
    {
        uint32_t initial_flows = max(kIpManipulatorSmuggleInitialFlows, (uint32_t) getTotalWorkersCount() * 8U);

        mutexInit(&state->synfin_flows_mutex);
        state->synfin_flows_capacity = initial_flows;
        state->synfin_flows          = memoryAllocateZero(sizeof(*state->synfin_flows) * initial_flows);
    }

    if (state->trick_ech_sni)
    {
        uint32_t initial_flows = max(kIpManipulatorSmuggleInitialFlows, (uint32_t) getTotalWorkersCount() * 8U);

        mutexInit(&state->echsni_flows_mutex);
        state->echsni_flows_capacity = initial_flows;
        state->echsni_flows          = memoryAllocateZero(sizeof(*state->echsni_flows) * initial_flows);
    }

    if (state->trick_smuggle_fin)
    {
        uint32_t initial_flows = max(kIpManipulatorSmuggleInitialFlows, (uint32_t) getTotalWorkersCount() * 8U);

        mutexInit(&state->smuggle_fin_mutex);
        state->smuggle_fin_flows_capacity = initial_flows;
        state->smuggle_fin_flows          = memoryAllocateZero(sizeof(*state->smuggle_fin_flows) * initial_flows);
        state->smuggle_fin_worker_states_count = (uint32_t) getTotalWorkersCount();
        state->smuggle_fin_worker_states =
            memoryAllocateZero(sizeof(*state->smuggle_fin_worker_states) * state->smuggle_fin_worker_states_count);
    }

    return t;
}
