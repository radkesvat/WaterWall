/*
 * Configuration compatibility and TLS host_name boundary tests for
 * IpManipulator. The compatibility rules are asserted directly through
 * ipmanipulatorValidateTrickCompatibility() so a specific validation result is
 * checked instead of only the create/destroy outcome, and the create path is
 * then exercised end to end for the settings that must be refused outright.
 */

#include "IpManipulator/interface.h"
#include "IpManipulator/structure.h"
#include "net/node_layer_solver.h"
#include "worker_registry_fixture.h"

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

typedef enum stateful_sni_trick_e
{
    kStatefulSniFirst = 0,
    kStatefulSniSmuggle,
    kStatefulSniOverlap,
    kStatefulSniSynfin,
    kStatefulSniEch,
    kStatefulSniCount
} stateful_sni_trick_e;

typedef struct upstream_action_case_s
{
    const char                       *name;
    size_t                            field_offset;
    enum tcp_bit_action_dynamic_value action;
} upstream_action_case_t;

static const char *const kStatefulSniNames[kStatefulSniCount] = {
    "first-sni",
    "smuggle-sni",
    "overlap-sni",
    "synfin-sni",
    "ech-sni-trick",
};

static const upstream_action_case_t kUpstreamActionCases[] = {
    {"up-tcp-bit-cwr", offsetof(ipmanipulator_tstate_t, up_tcp_bit_cwr_action), kDvsOn},
    {"up-tcp-bit-ece", offsetof(ipmanipulator_tstate_t, up_tcp_bit_ece_action), kDvsOff},
    {"up-tcp-bit-urg", offsetof(ipmanipulator_tstate_t, up_tcp_bit_urg_action), kDvsToggle},
    {"up-tcp-bit-ack", offsetof(ipmanipulator_tstate_t, up_tcp_bit_ack_action), kDvsOn},
    {"up-tcp-bit-psh", offsetof(ipmanipulator_tstate_t, up_tcp_bit_psh_action), kDvsPacketSyn},
    {"up-tcp-bit-rst", offsetof(ipmanipulator_tstate_t, up_tcp_bit_rst_action), kDvsOff},
    {"up-tcp-bit-syn", offsetof(ipmanipulator_tstate_t, up_tcp_bit_syn_action), kDvsToggle},
    {"up-tcp-bit-fin", offsetof(ipmanipulator_tstate_t, up_tcp_bit_fin_action), kDvsPacketAck},
};

static const upstream_action_case_t kDownstreamActionCases[] = {
    {"dw-tcp-bit-cwr", offsetof(ipmanipulator_tstate_t, down_tcp_bit_cwr_action), kDvsOn},
    {"dw-tcp-bit-psh", offsetof(ipmanipulator_tstate_t, down_tcp_bit_psh_action), kDvsToggle},
    {"dw-tcp-bit-fin", offsetof(ipmanipulator_tstate_t, down_tcp_bit_fin_action), kDvsOff},
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void applyAction(ipmanipulator_tstate_t *state, const upstream_action_case_t *action_case)
{
    enum tcp_bit_action_dynamic_value *field =
        (enum tcp_bit_action_dynamic_value *) (((uint8_t *) state) + action_case->field_offset);
    *field = action_case->action;
}

static void enableStatefulSni(ipmanipulator_tstate_t *state, stateful_sni_trick_e trick)
{
    switch (trick)
    {
    case kStatefulSniFirst:
        state->trick_first_sni = true;
        return;
    case kStatefulSniSmuggle:
        state->trick_smuggle_sni = true;
        return;
    case kStatefulSniOverlap:
        state->trick_overlap_sni = true;
        return;
    case kStatefulSniSynfin:
        state->trick_synfin_sni = true;
        return;
    case kStatefulSniEch:
    default:
        state->trick_ech_sni = true;
        return;
    }
}

static void testStatefulSniRejectsUpstreamActions(bool preserve_tcp_bitflags)
{
    for (uint32_t trick = 0; trick < (uint32_t) kStatefulSniCount; ++trick)
    {
        for (uint32_t i = 0; i < ARRAY_SIZE(kUpstreamActionCases); ++i)
        {
            ipmanipulator_tstate_t state = {0};

            enableStatefulSni(&state, (stateful_sni_trick_e) trick);
            applyAction(&state, &kUpstreamActionCases[i]);
            state.trick_preserve_tcp_bitflags = preserve_tcp_bitflags;

            char message[192];
            snprintf(message,
                     sizeof(message),
                     "%s with %s and preserve-tcp-bitflags=%s was not rejected",
                     kStatefulSniNames[trick],
                     kUpstreamActionCases[i].name,
                     preserve_tcp_bitflags ? "true" : "false");
            require(ipmanipulatorValidateTrickCompatibility(&state) ==
                        kIpManipulatorConfigRejectUpstreamTcpBitWithStatefulSni,
                    message);
        }
    }
}

static void testStatefulSniAcceptsDownstreamOnlyActions(void)
{
    for (uint32_t trick = 0; trick < (uint32_t) kStatefulSniCount; ++trick)
    {
        for (uint32_t i = 0; i < ARRAY_SIZE(kDownstreamActionCases); ++i)
        {
            ipmanipulator_tstate_t state = {0};

            enableStatefulSni(&state, (stateful_sni_trick_e) trick);
            applyAction(&state, &kDownstreamActionCases[i]);

            char message[192];
            snprintf(message,
                     sizeof(message),
                     "%s with downstream-only %s was rejected",
                     kStatefulSniNames[trick],
                     kDownstreamActionCases[i].name);
            require(ipmanipulatorValidateTrickCompatibility(&state) == kIpManipulatorConfigValid, message);

            state.trick_preserve_tcp_bitflags = true;
            require(ipmanipulatorValidateTrickCompatibility(&state) == kIpManipulatorConfigValid, message);
        }
    }
}

static void testStatefulSniAcceptsPreservationWithoutActions(void)
{
    for (uint32_t trick = 0; trick < (uint32_t) kStatefulSniCount; ++trick)
    {
        ipmanipulator_tstate_t state = {0};

        enableStatefulSni(&state, (stateful_sni_trick_e) trick);
        state.trick_preserve_tcp_bitflags = true;

        char message[192];
        snprintf(message,
                 sizeof(message),
                 "%s with preserve-tcp-bitflags and no TCP-bit action was rejected",
                 kStatefulSniNames[trick]);
        require(ipmanipulatorValidateTrickCompatibility(&state) == kIpManipulatorConfigValid, message);
    }
}

static void testSniBlenderPreservationRules(void)
{
    for (uint32_t i = 0; i < ARRAY_SIZE(kUpstreamActionCases); ++i)
    {
        ipmanipulator_tstate_t rejected = {0};

        rejected.trick_sni_blender           = true;
        rejected.trick_preserve_tcp_bitflags = true;
        applyAction(&rejected, &kUpstreamActionCases[i]);

        char message[192];
        snprintf(message,
                 sizeof(message),
                 "sni-blender with preserve-tcp-bitflags and %s was not rejected",
                 kUpstreamActionCases[i].name);
        require(ipmanipulatorValidateTrickCompatibility(&rejected) ==
                    kIpManipulatorConfigRejectPreservedTcpBitWithSniBlender,
                message);

        ipmanipulator_tstate_t accepted = {0};

        accepted.trick_sni_blender = true;
        applyAction(&accepted, &kUpstreamActionCases[i]);

        snprintf(message,
                 sizeof(message),
                 "sni-blender with %s and no preservation was rejected",
                 kUpstreamActionCases[i].name);
        require(ipmanipulatorValidateTrickCompatibility(&accepted) == kIpManipulatorConfigValid, message);
    }

    ipmanipulator_tstate_t downstream_only = {0};

    downstream_only.trick_sni_blender           = true;
    downstream_only.trick_preserve_tcp_bitflags = true;
    applyAction(&downstream_only, &kDownstreamActionCases[0]);
    require(ipmanipulatorValidateTrickCompatibility(&downstream_only) == kIpManipulatorConfigValid,
            "sni-blender with preservation and downstream-only actions was rejected");
}

static void testSniBlenderRejectsPortGhost(void)
{
    const char *const port_ghost_names[] = {
        "source-port-ghost",
        "dest-port-ghost",
    };

    for (uint32_t i = 0; i < ARRAY_SIZE(port_ghost_names); ++i)
    {
        ipmanipulator_tstate_t state = {.trick_sni_blender = true};

        if (i == 0)
        {
            state.trick_source_port_ghost = true;
        }
        else
        {
            state.trick_dest_port_ghost = true;
        }

        char message[160];
        snprintf(message, sizeof(message), "sni-blender with %s was accepted", port_ghost_names[i]);
        require(ipmanipulatorValidateTrickCompatibility(&state) == kIpManipulatorConfigRejectSniBlenderWithPortGhost,
                message);
    }
}

static void testTcpBitOnlyConfigurationsRemainValid(void)
{
    for (uint32_t i = 0; i < ARRAY_SIZE(kUpstreamActionCases); ++i)
    {
        ipmanipulator_tstate_t state = {0};

        applyAction(&state, &kUpstreamActionCases[i]);
        require(ipmanipulatorValidateTrickCompatibility(&state) == kIpManipulatorConfigValid,
                "an upstream TCP-bit-only configuration was rejected");

        state.trick_preserve_tcp_bitflags = true;
        require(ipmanipulatorValidateTrickCompatibility(&state) == kIpManipulatorConfigValid,
                "a preserved upstream TCP-bit-only configuration was rejected");

        state.trick_proto_swap = true;
        require(ipmanipulatorValidateTrickCompatibility(&state) == kIpManipulatorConfigValid,
                "a preserved TCP-bit configuration with protoswap was rejected");
    }

    ipmanipulator_tstate_t empty = {0};
    require(ipmanipulatorValidateTrickCompatibility(&empty) == kIpManipulatorConfigValid,
            "an empty configuration was rejected");
}

static void testStatefulSniCompositionMatrix(void)
{
    for (uint32_t first = 0; first < (uint32_t) kStatefulSniCount; ++first)
    {
        for (uint32_t second = first + 1U; second < (uint32_t) kStatefulSniCount; ++second)
        {
            ipmanipulator_tstate_t state = {0};
            enableStatefulSni(&state, (stateful_sni_trick_e) first);
            enableStatefulSni(&state, (stateful_sni_trick_e) second);
            require(ipmanipulatorValidateTrickCompatibility(&state) == kIpManipulatorConfigRejectMultipleStatefulSni,
                    "a pair of stateful SNI tricks was accepted in one node");
        }

        ipmanipulator_tstate_t blender = {0};
        enableStatefulSni(&blender, (stateful_sni_trick_e) first);
        blender.trick_sni_blender = true;
        require(ipmanipulatorValidateTrickCompatibility(&blender) ==
                    kIpManipulatorConfigRejectSniBlenderWithStatefulSni,
                "a stateful SNI trick with sni-blender was accepted in one node");

        ipmanipulator_tstate_t duplicate = {0};
        enableStatefulSni(&duplicate, (stateful_sni_trick_e) first);
        duplicate.trick_packet_duplicate = true;
        require(ipmanipulatorValidateTrickCompatibility(&duplicate) ==
                    kIpManipulatorConfigRejectPacketDuplicateWithStatefulSni,
                "a stateful SNI trick with packet-duplicate was accepted in one node");
    }

    ipmanipulator_tstate_t supported = {.trick_sni_blender = true, .trick_packet_duplicate = true};
    require(ipmanipulatorValidateTrickCompatibility(&supported) == kIpManipulatorConfigValid,
            "sni-blender plus packet-duplicate was rejected");
}

static node_t makeNode(const char *name, cJSON *settings)
{
    node_t node             = nodeIpManipulatorGet();
    node.name               = stringDuplicate(name);
    node.next               = stringDuplicate("normal-next");
    node.hash_name          = calcHashBytes(node.name, stringLength(node.name));
    node.hash_next          = calcHashBytes(node.next, stringLength(node.next));
    node.node_settings_json = settings;
    return node;
}

static void destroyNode(node_t *node)
{
    if (node->instance != NULL)
    {
        node->instance->onDestroy(node->instance, wwLifecycleStartupRollback());
        node->instance = NULL;
    }

    cJSON_Delete(node->node_settings_json);
    memoryFree(node->name);
    memoryFree(node->type);
    memoryFree(node->next);
    memoryZero(node, sizeof(*node));
}

static bool createSucceeds(cJSON *settings, const char *node_name)
{
    node_t    node = makeNode(node_name, settings);
    tunnel_t *t    = ipmanipulatorCreate(&node);

    node.instance = t;
    destroyNode(&node);
    return t != NULL;
}

static cJSON *makeEchSettings(size_t hostname_len)
{
    cJSON *settings = cJSON_CreateObject();
    require(settings != NULL, "failed to allocate ech-sni-trick settings");

    char *hostname = memoryAllocate(hostname_len + 1U);
    require(hostname != NULL, "failed to allocate the ech-sni-trick hostname fixture");
    memorySet(hostname, 'a', hostname_len);
    hostname[hostname_len] = '\0';

    require(cJSON_AddStringToObject(settings, "ech-sni-trick", hostname) != NULL,
            "failed to install the ech-sni-trick hostname fixture");
    memoryFree(hostname);
    return settings;
}

static void testEchHostnameLengthBoundary(void)
{
    require(createSucceeds(makeEchSettings(1), "ipm-ech-1"), "a one-byte ech-sni-trick hostname was rejected");
    require(createSucceeds(makeEchSettings(kIpManipulatorMaxTlsHostNameLen), "ipm-ech-255"),
            "a 255-byte ech-sni-trick hostname was rejected");
    require(! createSucceeds(makeEchSettings(kIpManipulatorMaxTlsHostNameLen + 1U), "ipm-ech-256"),
            "a 256-byte ech-sni-trick hostname was accepted");
    require(! createSucceeds(makeEchSettings(0), "ipm-ech-empty"), "an empty ech-sni-trick hostname was accepted");

    cJSON *non_string = cJSON_CreateObject();
    require(non_string != NULL && cJSON_AddNumberToObject(non_string, "ech-sni-trick", 42) != NULL,
            "failed to build a non-string ech-sni-trick fixture");
    require(! createSucceeds(non_string, "ipm-ech-number"), "a non-string ech-sni-trick value was accepted");
}

static void testCreateRejectsIncompatibleCombinations(void)
{
    cJSON *ech_with_upstream = cJSON_CreateObject();
    require(ech_with_upstream != NULL &&
                cJSON_AddStringToObject(ech_with_upstream, "ech-sni-trick", "cover.test") != NULL &&
                cJSON_AddStringToObject(ech_with_upstream, "up-tcp-bit-syn", "toggle") != NULL,
            "failed to build the incompatible ech/up-tcp-bit fixture");
    require(! createSucceeds(ech_with_upstream, "ipm-ech-up"),
            "ech-sni-trick with an upstream TCP-bit action was accepted");

    cJSON *ech_with_downstream = cJSON_CreateObject();
    require(ech_with_downstream != NULL &&
                cJSON_AddStringToObject(ech_with_downstream, "ech-sni-trick", "cover.test") != NULL &&
                cJSON_AddStringToObject(ech_with_downstream, "dw-tcp-bit-syn", "toggle") != NULL,
            "failed to build the compatible ech/dw-tcp-bit fixture");
    require(createSucceeds(ech_with_downstream, "ipm-ech-down"),
            "ech-sni-trick with a downstream-only TCP-bit action was rejected");

    cJSON *blender_preserved = cJSON_CreateObject();
    require(blender_preserved != NULL && cJSON_AddBoolToObject(blender_preserved, "sni-blender", true) != NULL &&
                cJSON_AddNumberToObject(blender_preserved, "sni-blender-packets", 4) != NULL &&
                cJSON_AddBoolToObject(blender_preserved, "preserve-tcp-bitflags", true) != NULL &&
                cJSON_AddStringToObject(blender_preserved, "up-tcp-bit-psh", "on") != NULL,
            "failed to build the preserved blender fixture");
    require(! createSucceeds(blender_preserved, "ipm-blender-preserved"),
            "sni-blender with preservation and an upstream action was accepted");

    cJSON *blender_plain = cJSON_CreateObject();
    require(blender_plain != NULL && cJSON_AddBoolToObject(blender_plain, "sni-blender", true) != NULL &&
                cJSON_AddNumberToObject(blender_plain, "sni-blender-packets", 4) != NULL &&
                cJSON_AddStringToObject(blender_plain, "up-tcp-bit-psh", "on") != NULL,
            "failed to build the plain blender fixture");
    require(createSucceeds(blender_plain, "ipm-blender-plain"),
            "sni-blender with a simple upstream action and no preservation was rejected");

    cJSON *blender_with_port_ghost = cJSON_Parse(
        "{\"sni-blender\":true,\"sni-blender-packets\":4,\"source-port-ghost\":true,\"dest-port-ghost\":true}");
    require(blender_with_port_ghost != NULL, "failed to build sni-blender/port-ghost JSON fixture");
    require(! createSucceeds(blender_with_port_ghost, "ipm-blender-port-ghost"),
            "the JSON create path accepted sni-blender with port ghost");

    cJSON *first_sni_preserved = cJSON_CreateObject();
    require(first_sni_preserved != NULL &&
                cJSON_AddStringToObject(first_sni_preserved, "first-sni", "cover.test") != NULL &&
                cJSON_AddBoolToObject(first_sni_preserved, "preserve-tcp-bitflags", true) != NULL,
            "failed to build the preserved first-sni fixture");
    require(createSucceeds(first_sni_preserved, "ipm-first-preserved"),
            "first-sni with preservation and no TCP-bit action was rejected");

    cJSON *first_with_blender =
        cJSON_Parse("{\"first-sni\":\"cover.test\",\"sni-blender\":true,\"sni-blender-packets\":2}");
    require(first_with_blender != NULL, "failed to build first-sni/blender JSON fixture");
    require(! createSucceeds(first_with_blender, "ipm-first-blender"),
            "the JSON create path accepted first-sni with sni-blender");

    cJSON *first_with_ech = cJSON_Parse("{\"first-sni\":\"cover.test\",\"ech-sni-trick\":\"cover.test\"}");
    require(first_with_ech != NULL, "failed to build the two-stateful-SNI JSON fixture");
    require(! createSucceeds(first_with_ech, "ipm-first-ech"), "the JSON create path accepted two stateful SNI tricks");

    cJSON *first_with_duplicate = cJSON_Parse("{\"first-sni\":\"cover.test\",\"packet-duplicate\":1}");
    require(first_with_duplicate != NULL, "failed to build first-sni/duplicate JSON fixture");
    require(! createSucceeds(first_with_duplicate, "ipm-first-duplicate"),
            "the JSON create path accepted first-sni with packet-duplicate");
}

static void testSniBlenderPacketRange(void)
{
    const int rejected[] = {0, 1, kSniBlenderTrickMaxPacketsCount + 1};
    for (uint32_t i = 0; i < ARRAY_SIZE(rejected); ++i)
    {
        cJSON *settings = cJSON_CreateObject();
        require(settings != NULL && cJSON_AddBoolToObject(settings, "sni-blender", true) != NULL &&
                    cJSON_AddNumberToObject(settings, "sni-blender-packets", rejected[i]) != NULL,
                "failed to build rejected sni-blender packet-count fixture");
        require(! createSucceeds(settings, "ipm-blender-range-reject"),
                "sni-blender accepted a packet count outside 2..16");
    }

    const int accepted[] = {kSniBlenderTrickMinPacketsCount, kSniBlenderTrickMaxPacketsCount};
    for (uint32_t i = 0; i < ARRAY_SIZE(accepted); ++i)
    {
        cJSON *settings = cJSON_CreateObject();
        require(settings != NULL && cJSON_AddBoolToObject(settings, "sni-blender", true) != NULL &&
                    cJSON_AddNumberToObject(settings, "sni-blender-packets", accepted[i]) != NULL,
                "failed to build accepted sni-blender packet-count fixture");
        require(createSucceeds(settings, "ipm-blender-range-accept"),
                "sni-blender rejected a packet count inside 2..16");
    }
}

static void testPacketAmplificationCountRanges(void)
{
    const int duplicate_rejected[] = {0, -1, kPacketDuplicateTrickMaxCount + 1};
    for (uint32_t i = 0; i < ARRAY_SIZE(duplicate_rejected); ++i)
    {
        cJSON *settings = cJSON_CreateObject();
        require(settings != NULL &&
                    cJSON_AddNumberToObject(settings, "packet-duplicate", duplicate_rejected[i]) != NULL,
                "failed to build rejected packet-duplicate fixture");
        require(! createSucceeds(settings, "ipm-packet-duplicate-range-reject"),
                "packet-duplicate accepted a count outside 1..16");
    }

    const int duplicate_accepted[] = {1, kPacketDuplicateTrickMaxCount};
    for (uint32_t i = 0; i < ARRAY_SIZE(duplicate_accepted); ++i)
    {
        cJSON *settings = cJSON_CreateObject();
        require(settings != NULL &&
                    cJSON_AddNumberToObject(settings, "packet-duplicate", duplicate_accepted[i]) != NULL,
                "failed to build accepted packet-duplicate fixture");
        require(createSucceeds(settings, "ipm-packet-duplicate-range-accept"),
                "packet-duplicate rejected a count inside 1..16");
    }

    const int first_sni_rejected[] = {0, -1, kFirstSniTrickMaxCount + 1};
    for (uint32_t i = 0; i < ARRAY_SIZE(first_sni_rejected); ++i)
    {
        cJSON *settings = cJSON_CreateObject();
        require(settings != NULL && cJSON_AddStringToObject(settings, "first-sni", "cover.test") != NULL &&
                    cJSON_AddNumberToObject(settings, "first-sni-count", first_sni_rejected[i]) != NULL,
                "failed to build rejected first-sni-count fixture");
        require(! createSucceeds(settings, "ipm-first-sni-count-range-reject"),
                "first-sni-count accepted a count outside 1..16");
    }

    const int first_sni_accepted[] = {1, kFirstSniTrickMaxCount};
    for (uint32_t i = 0; i < ARRAY_SIZE(first_sni_accepted); ++i)
    {
        cJSON *settings = cJSON_CreateObject();
        require(settings != NULL && cJSON_AddStringToObject(settings, "first-sni", "cover.test") != NULL &&
                    cJSON_AddNumberToObject(settings, "first-sni-count", first_sni_accepted[i]) != NULL,
                "failed to build accepted first-sni-count fixture");
        require(createSucceeds(settings, "ipm-first-sni-count-range-accept"),
                "first-sni-count rejected a count inside 1..16");
    }
}

static void testSniHoldTimeoutValidation(void)
{
    const int rejected[] = {0, -1};

    for (uint32_t i = 0; i < ARRAY_SIZE(rejected); ++i)
    {
        cJSON *overlap = cJSON_CreateObject();
        require(overlap != NULL && cJSON_AddStringToObject(overlap, "overlap-sni", "cover.test") != NULL &&
                    cJSON_AddNumberToObject(overlap, "overlap-sni-hold-timeout-ms", rejected[i]) != NULL,
                "failed to build rejected overlap-sni hold-timeout fixture");
        require(! createSucceeds(overlap, "ipm-overlap-hold-timeout-reject"),
                "overlap-sni accepted a non-positive hold timeout");

        cJSON *synfin = cJSON_CreateObject();
        require(synfin != NULL && cJSON_AddStringToObject(synfin, "synfin-sni", "cover.test") != NULL &&
                    cJSON_AddNumberToObject(synfin, "synfin-sni-hold-timeout-ms", rejected[i]) != NULL,
                "failed to build rejected synfin-sni hold-timeout fixture");
        require(! createSucceeds(synfin, "ipm-synfin-hold-timeout-reject"),
                "synfin-sni accepted a non-positive hold timeout");
    }
}

static void testOverlapSniStandaloneConfiguration(void)
{
    cJSON *settings = cJSON_CreateObject();
    require(settings != NULL && cJSON_AddStringToObject(settings, "overlap-sni", "cover.test") != NULL,
            "failed to build standalone overlap-sni fixture");
    require(createSucceeds(settings, "ipm-overlap-standalone"),
            "overlap-sni unexpectedly requires an auxiliary branch");
}

static void testNodeLayerMetadata(void)
{
    node_t    node   = nodeIpManipulatorGet();
    tunnel_t *t_ipm  = tunnelCreate(&node, 0, 0);
    node_t    n_head = {
           .name                  = (char *) "head",
           .type                  = (char *) "TunDevice",
           .flags                 = kNodeFlagChainHead,
           .layer_group           = kNodeLayer3,
           .layer_group_next_node = kNodeLayer3,
           .layer_group_prev_node = kNodeLayerNone,
           .can_have_next         = true,
           .can_have_prev         = false,
    };
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "PingServer",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer3,
        .can_have_next         = false,
        .can_have_prev         = true,
    };
    tunnel_t *t_head = tunnelCreate(&n_head, 0, 0);
    tunnel_t *t_tail = tunnelCreate(&n_tail, 0, 0);

    require(node.layer_group == kNodeLayer3, "IpManipulator does not advertise layer 3");
    require(node.layer_group_prev_node == kNodeLayerAnything && node.layer_group_next_node == kNodeLayerAnything,
            "IpManipulator unexpectedly restricts its neighboring layer groups");
    require(t_ipm != NULL && t_head != NULL && t_tail != NULL,
            "failed to build the IpManipulator chain classification fixture");

    t_head->next = t_ipm;
    t_ipm->prev  = t_head;
    t_ipm->next  = t_tail;
    t_tail->prev = t_ipm;

    tunnel_chain_t *chain = tunnelchainCreate(0);
    require(chain != NULL, "failed to create test chain");
    require(! chain->contains_packet_node, "an empty chain is already classified as a packet chain");

    tunnelchainInsert(chain, t_head);
    tunnelchainInsert(chain, t_ipm);
    tunnelchainInsert(chain, t_tail);

    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(chain, &status), "failed to solve chain containing IpManipulator");
    require(chain->contains_packet_node, "a chain containing IpManipulator was not classified as a packet chain");

    tunnelchainDestroy(chain);
    tunnelDestroy(t_head);
    tunnelDestroy(t_ipm);
    tunnelDestroy(t_tail);
    memoryFree(node.type);
}

int main(void)
{
    const uint32_t saved_workers_count = GSTATE.workers_count;

    GSTATE.workers_count = 2;
    testWorkerRegistryInstall(&g_test_worker_registry);

    require(globalstateInitializeSecureRandom(), "the operating system random source is unavailable");
    require(frandGlobalInit(), "fast random initialization failed");
    frandInit();

    testStatefulSniRejectsUpstreamActions(false);
    testStatefulSniRejectsUpstreamActions(true);
    testStatefulSniAcceptsDownstreamOnlyActions();
    testStatefulSniAcceptsPreservationWithoutActions();
    testSniBlenderPreservationRules();
    testSniBlenderRejectsPortGhost();
    testTcpBitOnlyConfigurationsRemainValid();
    testStatefulSniCompositionMatrix();
    testEchHostnameLengthBoundary();
    testCreateRejectsIncompatibleCombinations();
    testSniBlenderPacketRange();
    testPacketAmplificationCountRanges();
    testSniHoldTimeoutValidation();
    testOverlapSniStandaloneConfiguration();
    testNodeLayerMetadata();

    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    GSTATE.workers_count = saved_workers_count;
    testWorkerRegistryRestore(&g_test_worker_registry);
    printf("ALL unit tests passed!\n");
    return 0;
}
