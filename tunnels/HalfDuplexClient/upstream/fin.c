#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    halfduplexclient_lstate_t *ls = lineGetState(l, t);

    if (ls->upload_line)
    {
        line_t *upload_line = ls->upload_line;
        tunnelNextUpStreamFinish(t, upload_line);
        halfduplexclientLinestateDestroy(lineGetState(upload_line, t));
        lineDestroy(upload_line);
    }

    if (ls->download_line)
    {
        line_t *download_line = ls->download_line;
        tunnelNextUpStreamFinish(t, download_line);
        halfduplexclientLinestateDestroy(lineGetState(download_line, t));
        lineDestroy(download_line);
    }

    halfduplexclientLinestateDestroy(ls);

}
