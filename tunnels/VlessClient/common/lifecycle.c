#include "internal.h"

static void setLineProtocol(line_t *l, uint8_t protocol)
{
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(l), protocol);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(l), protocol);
}

void vlessclientTunnelstateDestroy(vlessclient_tstate_t *ts)
{
    assert(ts != NULL);

    addresscontextReset(&ts->target_addr);
    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}

void vlessclientStartUdpCarrier(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls)
{
    line_t               *carrier    = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(l));
    vlessclient_lstate_t *carrier_ls = lineGetState(carrier, t);
    vlessclientLinestateInitialize(carrier_ls, carrier);
    carrier_ls->tunnel           = t;
    carrier_ls->kind             = kVlessClientLineKindUdpCarrier;
    carrier_ls->application_line = l;
    addresscontextCopy(&carrier_ls->target_addr, &ls->target_addr);
    setLineProtocol(carrier, IP_PROTO_TCP);
    ls->carrier_line = carrier;
    tunnelNextUpStreamInit(t, carrier);
}

void vlessclientCloseLine(tunnel_t *t, line_t *l, vlessclient_close_origin_t origin)
{
    vlessclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVlessClientPhaseClosed)
        return;
    /* Both creation paths enter next-side Init before any callback can close the line. */
    if (ls->kind == kVlessClientLineKindDirect)
    {
        lineRef(l);
        vlessclientLinestateDestroy(ls);
        if (origin != kVlessClientCloseFromNext)
            tunnelNextUpStreamFinish(t, l);
        if (lineIsAlive(l) && origin != kVlessClientCloseFromPrev)
            tunnelPrevDownStreamFinish(t, l);
        lineUnref(l);
        return;
    }
    bool    from_application = ls->kind == kVlessClientLineKindUdpApplication;
    line_t *application      = from_application ? l : ls->application_line;
    line_t *carrier          = from_application ? ls->carrier_line : l;
    lineRef(application);
    lineRef(carrier);
    vlessclient_lstate_t *application_ls = lineGetState(application, t);
    vlessclient_lstate_t *carrier_ls     = lineGetState(carrier, t);
    application_ls->carrier_line         = NULL;
    carrier_ls->application_line         = NULL;
    vlessclientLinestateDestroy(application_ls);
    vlessclientLinestateDestroy(carrier_ls);
    if (from_application || origin != kVlessClientCloseFromNext)
        tunnelNextUpStreamFinish(t, carrier);
    if (lineIsAlive(carrier))
        lineDestroy(carrier);
    if (lineIsAlive(application) && (! from_application || origin != kVlessClientCloseFromPrev))
        tunnelPrevDownStreamFinish(t, application);
    lineUnref(carrier);
    lineUnref(application);
}
