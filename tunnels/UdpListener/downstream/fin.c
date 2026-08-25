#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    udplistenerRequireCurrentLineWorker(l, "downstream Finish");
    udplistener_lstate_t *lstate = lineGetState(l, t);

    if (lstate->source_kind == kUdpListenerSourceDynamic)
    {
        udplistener_tstate_t *ts  = tunnelGetState(t);
        wid_t                 wid = lineGetWID(l);

        if (wid < ts->workers_count)
        {
            udplistener_dynamic_endpoint_t *ep = udplistenerFindDynamicEndpoint(t, lstate->dynamic_handle);
            if (ep != NULL)
            {
                if (ep->line == l)
                {
                    ep->line = NULL;
                }
            }
        }

        udplistenerLinestateDestroy(lstate);
        lineDestroy(l);
        return;
    }

    local_idle_item_t *idle = lstate->idle_handle;

    if (idle == NULL)
    {
        LOGF("UdpListener: downstream Finish reached a line absent from the idle inventory");
        abortProgramNow(1);
    }

    lstate->idle_handle = NULL;
    bool deleted        = localidletableRemoveIdleItem(udpsockGetWorkerIdleTable(lstate->uio), idle);
    if (! deleted)
    {
        LOGE("UdpListener: Failed to remove idle item for UDP listener on FD:%x", lstate->listener_fd);
        abortProgramNow(1);
    }
    LOGD("UdpListener: Finished down stream for 1 connection on FD:%x", lstate->listener_fd);
    udplistenerLinestateDestroy(lstate);
    lineDestroy(l);
}
