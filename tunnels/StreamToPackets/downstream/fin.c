#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;

    LOGF("StreamToPackets: not supposed to receive downstream fin");
    abortProgramNow(1);
}
