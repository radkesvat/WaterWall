#include "structure.h"

#include "loggers/network_logger.h"

void pingserverUpStreamFinish(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamFinish(t, l);
}
