#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    halfduplexclient_lstate_t *ls = lineGetState(l, t);

    if (l == ls->download_line)
    {

        if (ls->upload_line)
        {
            tunnelNextUpStreamFinish(t, ls->upload_line);
            halfduplexclientLinestateDestroy(lineGetState(ls->upload_line, t));
            lineDestroy(ls->upload_line);
        }
    }
    else
    {
        if (ls->download_line)
        {
            tunnelNextUpStreamFinish(t, ls->download_line);
            halfduplexclientLinestateDestroy(lineGetState(ls->download_line, t));
            lineDestroy(ls->download_line);
        }
    }

    if (ls->main_line)
    {
        tunnelPrevdownStreamFinish(t, ls->main_line);
        halfduplexclientLinestateDestroy(lineGetState(ls->main_line, t));
    }
    
    halfduplexclientLinestateDestroy(ls);
    lineDestroy(l);
}
