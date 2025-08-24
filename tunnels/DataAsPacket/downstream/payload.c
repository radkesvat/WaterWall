#include "structure.h"

#include "loggers/network_logger.h"

static void localThreadDataaspacketTunnelDownStreamPayload(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard   worker;
    tunnel_t *t   = (tunnel_t *) arg1;
    line_t   *l   = (line_t *) arg2;
    sbuf_t   *buf = (sbuf_t *) arg3;

    dataaspacket_lstate_t *ls = lineGetState(l, t);

    if (ls->line == NULL || ls->paused)
    {
        bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}

void dataaspacketTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    dataaspacket_lstate_t *ls = lineGetState(l, t);

    tunnelPrevDownStreamPayload(t, tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l)), buf);
    if (ls->paused)
    {
        bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
        return;
    }

    if (ls->line == NULL)
    {
        for (wid_t wi = 0; wi < getWorkersCount(); wi++)
        {
            if (wi == lineGetWID(l))
            {
                continue;
            }
            line_t *line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), wi);
            if (line == NULL)
            {
                continue;
            }
            dataaspacket_lstate_t *wls = lineGetState(line, t);
            if (! wls->paused)
            {
                sendWorkerMessage(wi,localThreadDataaspacketTunnelDownStreamPayload,t,l,buf);
            }
        }
        bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
        return;
    }
    tunnelPrevDownStreamPayload(t, ls->line, buf);
}
