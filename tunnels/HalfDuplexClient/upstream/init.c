#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    halfduplexclient_lstate_t *ls = lineGetState(l, t);

    halfduplexclientLinestateInitialize(ls, l);

    ls->upload_line = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(l));

    halfduplexclient_lstate_t *ls_upline = lineGetState(ls->upload_line, t);
    halfduplexclientLinestateInitialize(ls_upline, l);
    ls_upline->upload_line = ls->upload_line;
    lineLock(ls->upload_line);
    tunnelNextUpStreamInit(t, ls->upload_line);
    if (! lineIsAlive(ls->upload_line))
    {
        lineUnlock(ls->upload_line);
        return;
    }
    lineUnlock(ls->upload_line);

    ls->download_line        = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(l));
    ls_upline->download_line = ls->download_line;

    halfduplexclient_lstate_t *ls_dwline = lineGetState(ls->download_line, t);
    halfduplexclientLinestateInitialize(ls_dwline, l);
    ls_dwline->upload_line   = ls->upload_line;
    ls_dwline->download_line = ls->download_line;

    lineLock(ls->download_line);
    tunnelNextUpStreamInit(t, ls->download_line);
    if (! lineIsAlive(ls->download_line))
    {
        lineUnlock(ls->download_line);
        return;
    }
    lineUnlock(ls->download_line);
}
