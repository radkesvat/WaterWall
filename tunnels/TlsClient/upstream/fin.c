#include "structure.h"
#include "race.h"
#include "sni_pool.h"

#include "loggers/network_logger.h"

void tlsclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{

    tlsclient_lstate_t *ls = lineGetState(l, t);

    if (tlsclientRaceIsMainLine(ls))
    {
        tlsclientRaceCloseMainLineFromUpstream(t, l);
        return;
    }

    if (tlsclientRaceIsChildLine(ls))
    {
        tlsclientRaceCloseChildLine(t, l, false);
        return;
    }

    tlsclientReleaseActiveSniLine(t, ls);
    tlsclientLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
}
