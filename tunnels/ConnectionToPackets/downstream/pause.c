#include "structure.h"

#include "loggers/network_logger.h"

void ctpTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    /*
     * A packet line carries every flow of one worker, so its backpressure is not
     * per-flow information. Applying it to every borrowed normal line would stall
     * unrelated connections, and there is no correct subset to apply it to.
     */
    LOGD("ConnectionToPackets: ignoring Pause on the packet line, it is not per-flow backpressure");
}
