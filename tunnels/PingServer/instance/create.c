#include "structure.h"

tunnel_t *pingserverCreate(node_t *node)
{
    return pingipv4NodeCreate(node, kPingIpv4Server);
}
