#include "structure.h"

#include "loggers/network_logger.h"

void packetstostreamTunnelDestroy(tunnel_t *t)
{
    packetstostream_tstate_t *ts    = tunnelGetState(t);
    tunnel_chain_t *chain = tunnelGetChain(t);

    if (ts->worker_timers != NULL)
    {
        for (wid_t wi = 0; wi < getWorkersCount(); ++wi)
        {
            if (ts->worker_timers[wi] != NULL)
            {
                weventSetUserData(ts->worker_timers[wi], NULL);
                wtimerDelete(ts->worker_timers[wi]);
                ts->worker_timers[wi] = NULL;
            }

            if (ts->worker_timeout_timers != NULL && ts->worker_timeout_timers[wi] != NULL)
            {
                weventSetUserData(ts->worker_timeout_timers[wi], NULL);
                wtimerDelete(ts->worker_timeout_timers[wi]);
                ts->worker_timeout_timers[wi] = NULL;
            }
        }
    }

    if (chain && chain->packet_lines)
    {
        for (wid_t wi = 0; wi < chain->workers_count; ++wi)
        {
            line_t *packet_line = tunnelchainGetWorkerPacketLine(chain, wi);

            if (packet_line == NULL)
            {
                continue;
            }

            packetstostream_lstate_t *ls = lineGetState(packet_line, t);

            if (ls->read_stream.pool != NULL)
            {
                packetstostreamLinestateDestroy(ls);
            }
        }
    }

    if (ts->worker_timers != NULL)
    {
        memoryFree(ts->worker_timers);
        ts->worker_timers = NULL;
    }

    if (ts->worker_timeout_timers != NULL)
    {
        memoryFree(ts->worker_timeout_timers);
        ts->worker_timeout_timers = NULL;
    }

    tunnelDestroy(t);
}
