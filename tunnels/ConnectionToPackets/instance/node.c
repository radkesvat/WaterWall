#include "interface.h"
#include "structure.h"

#include "loggers/network_logger.h"

/*
 * A layer-4 connection enters and raw layer-3 packets leave, so this node belongs
 * to both layer groups. Being a kNodeLayer3 member is what makes its chain a
 * packet chain and gets per-worker packet lines allocated for it.
 */
node_t nodeConnectionToPacketsGet(void)
{
    const char *type_name = "ConnectionToPackets";
    node_t      node_ctp  = {
              .name                  = NULL,
              .type                  = stringDuplicate(type_name),
              .next                  = NULL,
              .hash_name             = 0,
              .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
              .hash_next             = 0,
              .version               = 0003,
              .createHandle          = ctpTunnelCreate,
              .node_json             = NULL,
              .node_settings_json    = NULL,
              .node_manager_config   = NULL,
              .instance              = NULL,
              .flags                 = kNodeFlagNone,
              .required_padding_left = 0,
              .layer_group           = kNodeLayer3 | kNodeLayer4,
              .layer_group_next_node = kNodeLayer3,
              .layer_group_prev_node = kNodeLayer4,
              .can_have_next         = true,
              .can_have_prev         = true,
    };
    return node_ctp;
}
