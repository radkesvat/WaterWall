#include "wwapi.h"

typedef enum callback_kind_e
{
    kCallbackNone,
    kCallbackInit,
    kCallbackEst,
    kCallbackFinish,
    kCallbackPause,
    kCallbackResume,
} callback_kind_t;

typedef void (*lifecycle_callback_t)(tunnel_t *, line_t *);

static callback_kind_t observed_kind;
static tunnel_t       *observed_tunnel;
static line_t         *observed_line;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void recordCallback(tunnel_t *t, line_t *l, callback_kind_t kind)
{
    observed_kind   = kind;
    observed_tunnel = t;
    observed_line   = l;
}

static void recordInit(tunnel_t *t, line_t *l)
{
    recordCallback(t, l, kCallbackInit);
}

static void recordEst(tunnel_t *t, line_t *l)
{
    recordCallback(t, l, kCallbackEst);
}

static void recordFinish(tunnel_t *t, line_t *l)
{
    recordCallback(t, l, kCallbackFinish);
}

static void recordPause(tunnel_t *t, line_t *l)
{
    recordCallback(t, l, kCallbackPause);
}

static void recordResume(tunnel_t *t, line_t *l)
{
    recordCallback(t, l, kCallbackResume);
}

static void installRecorders(tunnel_t *t)
{
    t->fnInitU   = recordInit;
    t->fnInitD   = recordInit;
    t->fnEstU    = recordEst;
    t->fnEstD    = recordEst;
    t->fnFinU    = recordFinish;
    t->fnFinD    = recordFinish;
    t->fnPauseU  = recordPause;
    t->fnPauseD  = recordPause;
    t->fnResumeU = recordResume;
    t->fnResumeD = recordResume;
}

static void requireForwarded(lifecycle_callback_t callback, tunnel_t *packet_tunnel, tunnel_t *expected_tunnel,
                             callback_kind_t expected_kind, const char *message)
{
    line_t line = {0};

    observed_kind   = kCallbackNone;
    observed_tunnel = NULL;
    observed_line   = NULL;

    callback(packet_tunnel, &line);

    require(observed_kind == expected_kind, message);
    require(observed_tunnel == expected_tunnel, message);
    require(observed_line == &line, message);
}

static void testPacketTunnelLifecycleCallbacksPassThrough(void)
{
    tunnel_t *prev          = tunnelCreate(NULL, 0, 0);
    tunnel_t *packet_tunnel = packettunnelCreate(NULL, 0, 0);
    tunnel_t *next          = tunnelCreate(NULL, 0, 0);

    require(prev != NULL && packet_tunnel != NULL && next != NULL, "failed to create lifecycle test tunnels");

    tunnelBind(prev, packet_tunnel);
    tunnelBind(packet_tunnel, next);
    installRecorders(prev);
    installRecorders(next);

    requireForwarded(packet_tunnel->fnInitU,
                     packet_tunnel,
                     next,
                     kCallbackInit,
                     "packet tunnel did not forward upstream Init to next");
    requireForwarded(
        packet_tunnel->fnEstU, packet_tunnel, next, kCallbackEst, "packet tunnel did not forward upstream Est to next");
    requireForwarded(packet_tunnel->fnPauseU,
                     packet_tunnel,
                     next,
                     kCallbackPause,
                     "packet tunnel did not forward upstream Pause to next");
    requireForwarded(packet_tunnel->fnResumeU,
                     packet_tunnel,
                     next,
                     kCallbackResume,
                     "packet tunnel did not forward upstream Resume to next");
    requireForwarded(packet_tunnel->fnFinU,
                     packet_tunnel,
                     next,
                     kCallbackFinish,
                     "packet tunnel did not forward upstream Finish to next");

    requireForwarded(packet_tunnel->fnInitD,
                     packet_tunnel,
                     prev,
                     kCallbackInit,
                     "packet tunnel did not forward downstream Init to prev");
    requireForwarded(packet_tunnel->fnEstD,
                     packet_tunnel,
                     prev,
                     kCallbackEst,
                     "packet tunnel did not forward downstream Est to prev");
    requireForwarded(packet_tunnel->fnPauseD,
                     packet_tunnel,
                     prev,
                     kCallbackPause,
                     "packet tunnel did not forward downstream Pause to prev");
    requireForwarded(packet_tunnel->fnResumeD,
                     packet_tunnel,
                     prev,
                     kCallbackResume,
                     "packet tunnel did not forward downstream Resume to prev");
    requireForwarded(packet_tunnel->fnFinD,
                     packet_tunnel,
                     prev,
                     kCallbackFinish,
                     "packet tunnel did not forward downstream Finish to prev");

    require(packet_tunnel->fnPayloadU != tunnelDefaultUpStreamPayload,
            "packet tunnel unexpectedly inherited the upstream payload pass-through");
    require(packet_tunnel->fnPayloadD != tunnelDefaultDownStreamPayload,
            "packet tunnel unexpectedly inherited the downstream payload pass-through");

    tunnelDestroy(next);
    tunnelDestroy(packet_tunnel);
    tunnelDestroy(prev);
}

static void testFragmentPolicyPaths(void)
{
    node_t                     source_node    = {.type = (char[]) {"TunDevice"}};
    node_t                     stack_node     = {.type = (char[]) {"PacketsToConnection"}};
    node_t                     transform_node = {.type = (char[]) {"Disturber"}};
    node_t                     egress_node    = {.type = (char[]) {"RawSocket"}};
    tunnel_t                  *source         = tunnelCreate(&source_node, sizeof(packet_lifecycle_anchor_t), 0);
    tunnel_t                  *transform      = tunnelCreate(&transform_node, 0, 0);
    tunnel_t                  *stack          = tunnelCreate(&stack_node, 0, 0);
    tunnel_t                  *egress         = tunnelCreate(&egress_node, 0, 0);
    packet_lifecycle_anchor_t *anchor         = tunnelGetState(source);
    anchor->name                              = "test";
    anchor->direction                         = kPacketLifecycleAnchorPublishUpstream;
    tunnelBind(source, transform);
    tunnelBind(transform, stack);
    require(packettunnelValidateFragmentPath(source, kDeviceFragmentReassemble), "normalized stack path rejected");
    require(! packettunnelValidateFragmentPath(source, kDeviceFragmentPreserve), "raw path reached local stack");
    transform->next = egress;
    require(packettunnelValidateFragmentPath(source, kDeviceFragmentPreserve), "raw external path rejected");
    require(! packettunnelValidateFragmentPath(source, kDeviceFragmentReassemble),
            "normalized path reached limited egress");
    transform_node.type = (char[]) {"PacketsToStream"};
    require(! packettunnelValidateFragmentPath(source, kDeviceFragmentPreserve),
            "packet/stream path silently treated as I/O");
    transform_node.type = (char[]) {"Router"};
    require(! packettunnelValidateFragmentPath(source, kDeviceFragmentPreserve), "ambiguous routing accepted");
    anchor->direction = kPacketLifecycleAnchorPublishDownstream;
    source->prev      = stack;
    stack_node.type   = (char[]) {"ConnectionToPackets"};
    require(packettunnelValidateFragmentPath(source, kDeviceFragmentReassemble), "downstream local stack rejected");
    tunnelDestroy(source);
    tunnelDestroy(transform);
    tunnelDestroy(stack);
    tunnelDestroy(egress);
}

static void testFragmentPolicySettings(void)
{
    static const struct
    {
        const char              *json;
        device_fragment_policy_t expected;
    } cases[] = {
        {"{}", kDeviceFragmentReassemble},
        {"{\"fragment-policy\":\"reassemble\"}", kDeviceFragmentReassemble},
        {"{\"fragment-policy\":\"preserve-fragments\"}", kDeviceFragmentPreserve},
        {"{\"fragment-policy\":null}", kDeviceFragmentPolicyUnset},
        {"{\"fragment-policy\":false}", kDeviceFragmentPolicyUnset},
        {"{\"fragment-policy\":0}", kDeviceFragmentPolicyUnset},
        {"{\"fragment-policy\":[]}", kDeviceFragmentPolicyUnset},
        {"{\"fragment-policy\":{}}", kDeviceFragmentPolicyUnset},
        {"{\"fragment-policy\":\"\"}", kDeviceFragmentPolicyUnset},
        {"{\"fragment-policy\":\"invalid\"}", kDeviceFragmentPolicyUnset},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        cJSON *settings = cJSON_Parse(cases[i].json);
        require(settings != NULL, "failed to parse fragment policy settings");
        device_fragment_policy_t policy   = kDeviceFragmentPolicyUnset;
        const bool               accepted = packettunnelReadFragmentPolicy(settings, &policy);
        require(accepted == (cases[i].expected != kDeviceFragmentPolicyUnset),
                "fragment policy setting was incorrectly accepted or rejected");
        if (accepted)
        {
            require(policy == cases[i].expected, "fragment policy default or explicit value was not retained");
        }
        cJSON_Delete(settings);
    }
}

int main(void)
{
    testPacketTunnelLifecycleCallbacksPassThrough();
    testFragmentPolicyPaths();
    testFragmentPolicySettings();
    return 0;
}
