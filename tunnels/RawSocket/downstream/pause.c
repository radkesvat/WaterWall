#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketDownStreamPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("This Function is not supposed to be called (RawSocket)");
    terminateProgram(1);
}
