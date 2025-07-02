#include "structure.h"

#include "loggers/network_logger.h"

void ipmanipulatorUpStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("This Function is not supposed to be called, used packet-tunnel interface instead (IpManipulator)");
    terminateProgram(1);
}
