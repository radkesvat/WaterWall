#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    // A packet line never finishes: reaching here means the packet-line
    // lifecycle is corrupted, and this runs on a worker. Hard-abort.
    LOGF("TunDevice: unexpected downstream Finish on worker packet line %u", (unsigned int) lineGetWID(l));
    abortProgramNow(1);
}
