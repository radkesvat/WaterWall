#include "structure.h"

#include "loggers/network_logger.h"

void authenticationclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("AuthenticationClient: UpStreamFinish is disabled");
    terminateProgram(1);
}
