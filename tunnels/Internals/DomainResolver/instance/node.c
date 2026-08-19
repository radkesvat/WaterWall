#include "interface.h"
#include "structure.h"

node_t nodeDomainResolverGet(void)
{
    const char *type_name           = "DomainResolver";
    node_t      node_domainresolver = {
             .name                  = NULL,
             .type                  = stringDuplicate(type_name),
             .next                  = NULL,
             .hash_name             = 0,
             .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
             .hash_next             = 0,
             .version               = 0001,
             .createHandle          = domainresolverTunnelCreate,
             .node_json             = NULL,
             .node_settings_json    = NULL,
             .node_manager_config   = NULL,
             .instance              = NULL,
             .flags                 = kNodeFlagNone,
             .required_padding_left = 0,
             .layer_group           = kNodeLayerAnything,
             .layer_group_next_node = kNodeLayerSameAsPrev,
             .layer_group_prev_node = kNodeLayerSameAsNext,
             .can_have_next         = true,
             .can_have_prev         = true,
    };
    return node_domainresolver;
}
