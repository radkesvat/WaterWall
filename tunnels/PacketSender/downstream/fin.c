#include "structure.h"

#include "loggers/network_logger.h"

void packetsenderTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    // Absorbing this is the whole job, and it is a normal event rather than a
    // contract violation: a stream adapter may sit at the far end of the packet
    // line and close its own side for its own reasons. `PacketSender -> UdpConnector`
    // does exactly that when a UDP flow expires, and the Finish travels back down
    // the worker packet line to here.
    //
    // PacketSender owns no per-line state, has no prev to forward to, and does not
    // use Finish as a completion signal - the send loop is timer-driven. The packet
    // line itself belongs to the chain and is destroyed only by tunnelchainDestroy(),
    // so there is nothing to release and nothing to destroy.
    discard l;
}
