#include "structure.h"

#include "loggers/network_logger.h"

void authenticationclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("AuthenticationClient: UpStreamResume is disabled");
    terminateProgram(1);
}
