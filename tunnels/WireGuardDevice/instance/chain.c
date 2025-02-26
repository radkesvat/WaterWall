#include "structure.h"

#include "loggers/network_logger.h"

void wireguarddeviceTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    // using tunnel / adapter default handle for this action
    discard t;
    discard chain;
    LOGF("This Function is disabled, using the default PacketTunnel instead");
    exit(1);
    
}
