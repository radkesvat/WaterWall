#include "structure.h"

tunnel_t *pingclientCreate(node_t *node)
{
    return pingipv4NodeCreate(node, kPingIpv4Client);
}
