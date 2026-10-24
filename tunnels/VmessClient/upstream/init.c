#include "internal.h"

#include "loggers/network_logger.h"

void vmessclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    vmessclient_tstate_t *ts     = tunnelGetState(t);
    vmessclient_lstate_t *ls     = lineGetState(l, t);
    address_context_t    *target = lineGetDestinationAddressContext(l);

    vmessclientLinestateInitialize(ls, l);
    ls->tunnel = t;
    if (! wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(l))))
    {
        vmessclientLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    /* With local DNS, the prepare hook already applied the target before resolution. */
    if (! ts->resolve_domains && UNLIKELY(! vmessclientApplyTargetContext(t, l)))
    {
        vmessclientLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    assert(target->proto_tcp != target->proto_udp);

    ls->tunnel = t;
    ls->kind   = target->proto_udp ? kVmessClientLineKindUdpApplication : kVmessClientLineKindDirect;
    addresscontextCopy(&ls->target_addr, target);

    if (ts->verbose)
    {
        LOGD("VmessClient: line init protocol=%s port=%u",
             ls->kind == kVmessClientLineKindDirect ? "tcp" : "udp",
             (unsigned int) target->port);
    }

    if (ls->kind == kVmessClientLineKindUdpApplication)
    {
        vmessclientStartUdpCarrier(t, l, ls);
        return;
    }

    tunnelNextUpStreamInit(t, l);
}
