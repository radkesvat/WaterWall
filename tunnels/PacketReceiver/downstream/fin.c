#include "structure.h"

#include "loggers/network_logger.h"

void packetreceiverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    // The mirror of the upstream handler: PacketReceiver can sit at either end of
    // a chain, owns no per-line state either way, and never treats Finish as a
    // completion signal. See upstream/fin.c for why absorbing it is correct.
    discard l;
}
