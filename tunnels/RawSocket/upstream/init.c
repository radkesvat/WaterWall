#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketUpStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    // since its  an adapter node we should only ignore since this callabck is taked in place of packet tunnels one
    // LOGF("This Function is not supposed to be called, used packet-tunnel interface instead  (RawSocket)");
    // terminateProgram(1);

}
