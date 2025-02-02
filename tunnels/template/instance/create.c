#include "structure.h"

tunnel_t* templateTunnelCreate(node_t* node)
{
    return tunnelCreate(node, sizeof(template_tstate_t), sizeof(template_lstate_t));
}
