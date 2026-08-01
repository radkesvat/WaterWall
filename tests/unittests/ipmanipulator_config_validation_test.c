/*
 * Configuration compatibility and TLS host_name boundary tests for
 * IpManipulator. The compatibility rules are asserted directly through
 * ipmanipulatorValidateTrickCompatibility() so a specific validation result is
 * checked instead of only the create/destroy outcome, and the create path is
 * then exercised end to end for the settings that must be refused outright.
 */

#include "IpManipulator/interface.h"
#include "IpManipulator/structure.h"

#include "global_state.h"

#include <stdio.h>
#include <stdlib.h>

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
        node->instance->onDestroy(node->instance);
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

    cJSON *first_sni_preserved = cJSON_CreateObject();
    require(first_sni_preserved != NULL &&
                cJSON_AddStringToObject(first_sni_preserved, "first-sni", "cover.test") != NULL &&
                cJSON_AddBoolToObject(first_sni_preserved, "preserve-tcp-bitflags", true) != NULL,
            "failed to build the preserved first-sni fixture");
    require(createSucceeds(first_sni_preserved, "ipm-first-preserved"),
            "first-sni with preservation and no TCP-bit action was rejected");
}

int main(void)
{
    const uint32_t saved_workers_count = GSTATE.workers_count;

    GSTATE.workers_count = 2;

    /* Creating a tunnel now builds bounded flow tables, which need a secure seed. */
    require(globalstateInitializeSecureRandom(), "the operating system random source is unavailable");

    testStatefulSniRejectsUpstreamActions(false);
    testStatefulSniRejectsUpstreamActions(true);
    testStatefulSniAcceptsDownstreamOnlyActions();
    testStatefulSniAcceptsPreservationWithoutActions();
    testSniBlenderPreservationRules();
    testTcpBitOnlyConfigurationsRemainValid();
    testEchHostnameLengthBoundary();
    testCreateRejectsIncompatibleCombinations();

    globalstateDestroySecureRandom();
    GSTATE.workers_count = saved_workers_count;
    printf("ALL unit tests passed!\n");
    return 0;
}
