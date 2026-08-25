#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard               context;
    udplistener_tstate_t *ts = tunnelGetState(t);
    atomic_store_explicit(&ts->dynamic_admission_open, false, memory_order_release);
}

void udplistenerTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    if (! currentThreadIsEventWorkerWID(wid))
    {
        LOGF("UdpListener: worker quiesce arrived outside worker %u", (unsigned int) wid);
        abortProgramNow(1);
    }

    udplistener_tstate_t *ts = tunnelGetState(t);

    if (wid < ts->workers_count)
    {
        udplistener_worker_registry_t *reg = &ts->worker_registries[wid];
        c_foreach(it, udplistener_endpoint_map_t, reg->endpoints)
        {
            udplistener_dynamic_endpoint_t *ep = it.ref->second;
            ep->state                          = kDynamicEndpointClosing;
            if (ep->wio != NULL)
            {
                weventSetUserData(ep->wio, NULL);
                wioSetCallBackRead(ep->wio, NULL);
                wioClose(ep->wio);
                ep->wio = NULL;
            }
        }
    }
}

void udplistenerTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    if (! currentThreadIsEventWorkerWID(wid))
    {
        LOGF("UdpListener: worker stop arrived outside worker %u", (unsigned int) wid);
        abortProgramNow(1);
    }

    udplistener_tstate_t *ts = tunnelGetState(t);

    if (wid < ts->workers_count)
    {
        udplistener_worker_registry_t *reg = &ts->worker_registries[wid];
        while (udplistener_endpoint_map_t_size(&reg->endpoints) > 0)
        {
            udplistener_endpoint_map_t_iter it = udplistener_endpoint_map_t_begin(&reg->endpoints);
            udplistenerDynamicEndpointClose(t, it.ref->second->handle);
        }
    }
}

void udplistenerTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    discard t;
}
