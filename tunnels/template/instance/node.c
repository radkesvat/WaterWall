#include "interface.h"
#include "structure.h"

node_t nodeTemplateGet(void)
{
    const char* type_name = "Template";
    node_t node_template = {
        .name                  = NULL,
        .type                  = stringDuplicate(type_name),
        .next                  = NULL,
        .hash_name             = 0,
        .hash_type             = calcHashBytes(type_name, strlen(type_name)),
        .hash_next             = 0,
        .version               = 0001,
        .createHandle          = templateTunnelCreate,
        .destroyHandle         = templateTunnelDestroy,
        .apiHandle             = templateTunnelApi,
        .node_json             = NULL,
        .node_settings_json    = NULL,
        .node_manager_config   = NULL,
        .instance              = NULL,
        .flags                 = kNodeFlagChainHead,
        .required_padding_left = 0,
    };
    return node_template;
}
