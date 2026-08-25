#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udplistenerRequireCurrentLineWorker(l, "downstream Payload");
    udplistener_lstate_t *ls = lineGetState(l, t);

    if (ls->source_kind == kUdpListenerSourceStatic)
    {
        localidletableKeepIdleItemForAtleast(udpsockGetWorkerIdleTable(ls->uio), ls->idle_handle, kUdpKeepExpireTime);
        postUdpWrite(ls->uio, lineGetWID(l), buf, ls->peer_addr);
        return;
    }

    if (ls->source_kind == kUdpListenerSourceDynamic)
    {
        udplistener_tstate_t *ts  = tunnelGetState(t);
        wid_t                 wid = lineGetWID(l);

        if (wid >= ts->workers_count)
        {
            lineReuseBuffer(l, buf);
            return;
        }

        udplistener_dynamic_endpoint_t *ep = udplistenerFindDynamicEndpoint(t, ls->dynamic_handle);
        if (ep != NULL && ep->line == l && ep->state == kDynamicEndpointActive && ep->wio != NULL &&
            ! wioIsClosed(ep->wio) && ls->bound_local_port != 0 && ep->bound_local_port == ls->bound_local_port &&
            sockaddrPort(&ep->pinned_peer_addr) != 0)
        {
            // wioWriteDatagram consumes/reuses buf on all execution paths.
            wioWriteDatagram(ep->wio, buf, &ep->pinned_peer_addr);
            return;
        }

        lineReuseBuffer(l, buf);
        return;
    }

    lineReuseBuffer(l, buf);
}
