#include "interface.h"
#include "internal.h"

node_t nodeVmessServerGet(void)
{
    const char *type_name        = "VmessServer";
    node_t      node_vmessserver = {
             .name                  = NULL,
             .type                  = stringDuplicate(type_name),
             .next                  = NULL,
             .hash_name             = 0,
             .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
             .hash_next             = 0,
             .version               = 0001,
             .createHandle          = vmessserverTunnelCreate,
             .node_json             = NULL,
             .node_settings_json    = NULL,
             .node_manager_config   = NULL,
             .instance              = NULL,
             .flags                 = kNodeFlagBlocksSplice,
             .required_padding_left = 0,
             .layer_group           = kNodeLayer4,
             .layer_group_next_node = kNodeLayer4,
             .layer_group_prev_node = kNodeLayer4,
             .can_have_next         = true,
             .can_have_prev         = true,
    };
    return node_vmessserver;
}
