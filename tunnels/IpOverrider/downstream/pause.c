#include "structure.h"

#include "loggers/network_logger.h"

void ipoverriderDownStreamPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("This Function is not supposed to be called, used packet-tunnel interface instead (IpOverrider)");
    terminateProgram(1);
}
