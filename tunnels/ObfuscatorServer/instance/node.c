#include "interface.h"
#include "structure.h"

#include "loggers/network_logger.h"

node_t nodeObfuscatorServerGet(void)
{
    const char *type_name     = "ObfuscatorServer";
    node_t      node_obfuscatorserver = {
             .name                  = NULL,
             .type                  = stringDuplicate(type_name),
             .next                  = NULL,
             .hash_name             = 0,
             .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
             .hash_next             = 0,
             .version               = 0001,
             .createHandle          = obfuscatorserverTunnelCreate,
             .node_json             = NULL,
             .node_settings_json    = NULL,
             .node_manager_config   = NULL,
             .instance              = NULL,
             .flags                 = kNodeFlagNone,
             .required_padding_left = kObfuscatorTlsRecordHeaderSize,
             .layer_group           = kNodeLayerAnything,
             .layer_group_next_node = kNodeLayerSameAsPrev,
             .layer_group_prev_node = kNodeLayerSameAsNext,
             .can_have_next         = true,
             .can_have_prev         = true,
    };
    return node_obfuscatorserver;
}
