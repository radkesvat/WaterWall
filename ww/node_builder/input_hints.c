#include "input_hints.h"
#include "loggers/internal_logger.h"
#include "net/node_layer_solver.h"

static tunnel_t *refuseInputHint(node_t *node);

const char *nodeInputHintUnresolvedDiagnostic(const node_t *node)
{
    if (node->createHandle != refuseInputHint)
    {
        return NULL;
    }

    const node_layer_domain_t layer = nodeLayerGroupToDomain(node->layer_group);
    assert(layer == kLayerDomainL3 || layer == kLayerDomainL4);
    if (layer == kLayerDomainL3)
    {
        return "HintPacketIN requires a packet input. Replace this hint with a concrete input before starting "
               "WaterWall.";
    }
    return "HintConnectionIN requires a connection input. Replace this hint with a concrete input before starting "
           "WaterWall.";
}

static tunnel_t *refuseInputHint(node_t *node)
{
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    LOGF("%s", nodeInputHintUnresolvedDiagnostic(node));
    startupFailureRecord(1);
    discard wwStartupContextEnd(&startup);
    return NULL;
}

static node_t makeInputHint(const char *type, enum node_layer_group layer)
{
    return (node_t) {
        .type                  = stringDuplicate(type),
        .hash_type             = calcHashBytes(type, stringLength(type)),
        .version               = 1,
        .flags                 = kNodeFlagChainHead,
        .required_padding_left = 0,
        .createHandle          = refuseInputHint,
        .layer_group           = layer,
        .layer_group_next_node = layer,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
}

node_t nodeHintConnectionINGet(void)
{
    return makeInputHint("HintConnectionIN", kNodeLayer4);
}

node_t nodeHintPacketINGet(void)
{
    return makeInputHint("HintPacketIN", kNodeLayer3);
}
