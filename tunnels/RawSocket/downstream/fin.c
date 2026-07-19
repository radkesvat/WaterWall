#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketDownStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    LOGF("RawSocket: unexpected downstream Finish on worker packet line %u", (unsigned int) lineGetWID(l));
    terminateProgram(1);
}
