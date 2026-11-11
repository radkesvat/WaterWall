#include "internal.h"
#include "loggers/network_logger.h"

void vmessclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    vmessclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVmessClientPhaseClosed || ls->closing || ls->kind == kVmessClientLineKindUdpApplication ||
        sbufGetLength(buf) == 0)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    vmessclient_tstate_t *ts = tunnelGetState(t);
    atomicAddU64Explicit(&ts->stats.rx_wire_bytes, sbufGetLength(buf), memory_order_relaxed);
    assert(! sbufIsSplice(buf));
    buf = vmessclientCompactInput(l, buf);
    if (! ls->request_sent || ! bufferqueueTryPushBack(&ls->pending_down, &buf))
    {
        if (! ls->request_sent)
            LOGW("VmessClient: closing connection: received wire data before request submission (incoming_bytes=%zu)",
                 sbufGetLength(buf));
        else
        {
            const buffer_budget_cost_t usage           = bufferbudgetGetUsage(&ls->downstream_budget);
            const buffer_budget_cost_t limits          = bufferbudgetGetLimits(&ls->downstream_budget);
            const size_t               incoming_bytes  = sbufGetLength(buf);
            const size_t               incoming_charge = sbufGetQueueCharge(buf);
            LOGW("VmessClient: closing connection: downstream ordering queue refused: %s "
                 "(retained_bytes=%zu, incoming_bytes=%zu, limit_bytes=%zu, retained_charge_bytes=%zu, "
                 "incoming_charge_bytes=%zu, limit_charge_bytes=%zu)",
                 incoming_bytes > limits.bytes - usage.bytes      ? "byte budget exceeded"
                 : incoming_charge > limits.charge - usage.charge ? "storage charge budget exceeded"
                                                                  : "queue admission failed",
                 usage.bytes,
                 incoming_bytes,
                 limits.bytes,
                 usage.charge,
                 incoming_charge,
                 limits.charge);
        }
        lineReuseBuffer(l, buf);
        vmessclientSetReason(ls, kVmessClientReasonRetainedInput);
        vmessclientCloseLine(t, l, kVmessClientCloseInternal);
        return;
    }
    vmessclientReceive(t, l);
}
