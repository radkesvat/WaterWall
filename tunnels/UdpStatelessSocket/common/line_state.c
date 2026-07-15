#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketLinestateInitialize(udpstatelesssocket_lstate_t *ls, line_t *l, tunnel_t *t,
                                           local_idle_item_t *idle_handle, const sockaddr_u *peer_addr,
                                           const sockaddr_u *local_addr)
{
    assert(ls != NULL);
    assert(l != NULL);
    assert(t != NULL);
    assert(idle_handle != NULL);
    assert(peer_addr != NULL);
    assert(local_addr != NULL);

    addresscontextFromSockAddrWithProtocol(&l->routing_context.src_ctx, peer_addr, IP_PROTO_UDP);
    l->routing_context.peer_source_port    = sockaddrPort((sockaddr_u *) peer_addr);
    l->routing_context.local_listener_port = sockaddrPort((sockaddr_u *) local_addr);
    addresscontextFromSockAddrWithProtocol(&l->routing_context.dest_ctx, local_addr, IP_PROTO_UDP);

    *ls = (udpstatelesssocket_lstate_t) {
        .tunnel           = t,
        .line             = l,
        .idle_handle      = idle_handle,
        .peer_addr        = *peer_addr,
        .local_addr       = *local_addr,
        .read_paused      = false,
    };
}

void udpstatelesssocketLinestateDestroy(udpstatelesssocket_lstate_t *ls)
{
    if (ls->idle_handle != NULL)
    {
        LOGF("UdpStatelessSocket: idle item still exists while destroying peer line state");
        terminateProgram(1);
    }
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(udpstatelesssocket_lstate_t)));
}
