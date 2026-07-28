#include "structure.h"

#include "loggers/network_logger.h"

void pingclientDownStreamPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("This Function is not supposed to be called, used packet-tunnel interface instead (PingClient)");
    abortProgramNow(1);
}
