#include "structure.h"

#include "loggers/network_logger.h"

/*
 * Rejecting happens before anything was published, so the only obligations are
 * releasing this node's own line state and telling prev - the line's owner -
 * that the flow is over. The line itself is never destroyed here.
 */
static void ctpRejectLine(tunnel_t *t, line_t *l, ctp_lstate_t *ls)
{
    ctpLinestateDestroy(ls);
    if (ctpPrevGateEnter(t))
    {
        tunnelPrevDownStreamFinish(t, l);
        ctpPrevGateLeave(t);
    }
}

static void ctpFailEstablishedTaskAdmission(tunnel_t *t, line_t *l)
{
    LOGF("ConnectionToPackets: failed to admit required established task");
    ctpCloseLineTowardPrevWithoutDrain(t, l);
    if (! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
}

void ctpTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    if (UNLIKELY(ctpLineIsPacketLine(t, l)))
    {
        LOGF("ConnectionToPackets: unexpected upstream Init on the packet line");
        abortProgramNow(1);
        return;
    }

    ctp_tstate_t                 *ts       = tunnelGetState(t);
    ctp_lstate_t                 *ls       = lineGetState(l, t);
    address_context_t            *dest_ctx = lineGetDestinationAddressContext(l);
    ctp_domain_resolver_lstate_t *rls      = domainresolverTunnelGetUserLineState(ts->domain_resolver_tunnel, l);

    if (UNLIKELY(rls == NULL))
    {
        LOGF("ConnectionToPackets: internal DomainResolver prepare state is missing");
        abortProgramNow(1);
        return;
    }

    const ctp_line_kind_t kind = rls->protocol == IP_PROTO_UDP ? kCtpLineKindUdp : kCtpLineKindTcp;

    // Line state exists before any resolver, lwIP or scheduling work can observe it.
    if (UNLIKELY(! ctpLinestateInitialize(ls, t, l, kind)))
    {
        /*
         * This flow's queue could not be allocated. No state was published and no
         * line reference is held, so the only thing owed is the close report to
         * prev, which owns the line. Other flows are unaffected.
         */
        LOGW("ConnectionToPackets: out of memory starting a flow; refusing it");
        if (ctpPrevGateEnter(t))
        {
            tunnelPrevDownStreamFinish(t, l);
            ctpPrevGateLeave(t);
        }
        return;
    }

    if (UNLIKELY(ctpTunnelIsStopping(t)))
    {
        LOGD("ConnectionToPackets: refusing a new flow because the node is stopping");
        ctpRejectLine(t, l, ls);
        return;
    }

    if (! addresscontextCanConvertToSockAddr(dest_ctx) || ! addresscontextHasPort(dest_ctx))
    {
        LOGE("ConnectionToPackets: destination address or port is not initialized");
        ctpRejectLine(t, l, ls);
        return;
    }

    if (dest_ctx->ip_address.type != IPADDR_TYPE_V4)
    {
        // The node is IPv4-only by design. Configuration already refuses an
        // IPv6-selecting domain-strategy, so reaching here means a literal IPv6
        // destination or a chain that resolved one on this node's behalf.
        LOGE("ConnectionToPackets: this node emits IPv4 only, but the destination is IPv6. "
             "Give this chain an IPv4 destination");
        ctpRejectLine(t, l, ls);
        return;
    }

    if (ls->kind == (uint8_t) kCtpLineKindUdp)
    {
        if (! ctpUdpOpenFlow(t, l, ls, &dest_ctx->ip_address, dest_ctx->port))
        {
            ctpRejectLine(t, l, ls);
            return;
        }

        // A connected UDP pcb is usable the moment it is registered, but Est is
        // still scheduled so prev is never re-entered from inside its own Init.
        ls->connected                          = true;
        const line_task_submit_result_e result = lineScheduleTask(l, ctpEstablishedTask, t, NULL);
        if (result == kLineTaskSubmitRejectedSettled)
        {
            ctpFailEstablishedTaskAdmission(t, l);
        }
        else
        {
            assert(result == kLineTaskSubmitAcceptedAsync);
        }
        return;
    }

    if (! ctpTcpOpenFlow(t, l, ls, &dest_ctx->ip_address, dest_ctx->port))
    {
        ctpRejectLine(t, l, ls);
        return;
    }

    if (! ctpArmConnectDeadline(t, l, ls))
    {
        /*
         * Without the deadline this connect would have no bound at all, so the
         * flow is torn down here rather than started and left to hang. The pcb
         * has to go back before the line state does.
         */
        LOGE("ConnectionToPackets: could not arm the connect deadline timer, refusing the flow");
        LOCK_TCPIP_CORE();
        ctpDetachFlowLocked(t, ls, false);
        UNLOCK_TCPIP_CORE();
        ctpRejectLine(t, l, ls);
    }
}
