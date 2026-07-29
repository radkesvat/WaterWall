#include "structure.h"

#include "loggers/network_logger.h"

void packetreceiverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    // Absorbing this is the whole job. PacketReceiver terminates the chain, so
    // there is no next to forward to; it owns no per-line state, so there is
    // nothing to release; and its completion is timer- and report-driven, never
    // signalled by Finish.
    //
    // The line here is whatever its prev is built on. `UdpListener -> PacketReceiver`
    // finishes an ordinary accepted line when the peer expires, which PacketReceiver
    // borrows and must not destroy; a layer-3 prev finishes the chain's worker packet
    // line, which belongs to the chain and is destroyed only by tunnelchainDestroy().
    // Either way the correct response is to do nothing.
    discard l;
}
