#include "structure.h"

static void setLineProtocol(line_t *l, uint8_t protocol)
{
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(l), protocol);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(l), protocol);
}

static line_t *createInternalLine(tunnel_t *t, line_t *application_l, vlessclient_line_kind_t kind)
{
    line_t *inner_l = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(application_l));

    vlessclient_lstate_t *inner_ls = lineGetState(inner_l, t);
    vlessclientLinestateInitialize(inner_ls, inner_l);
    inner_ls->tunnel   = t;
    inner_ls->kind     = kind;
    inner_ls->application_line = application_l;

    return inner_l;
}

void vlessclientTunnelstateDestroy(vlessclient_tstate_t *ts)
{
    assert(ts != NULL);

    addresscontextReset(&ts->target_addr);
    memoryZero(ts->uuid, sizeof(ts->uuid));
    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}

void vlessclientStartUdpCarrier(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls)
{
    line_t               *carrier    = createInternalLine(t, l, kVlessClientLineKindUdpCarrier);
    vlessclient_lstate_t *carrier_ls = lineGetState(carrier, t);
    addresscontextCopy(&carrier_ls->target_addr, &ls->target_addr);
    carrier_ls->protocol = ls->protocol;
    setLineProtocol(carrier, IP_PROTO_TCP);
    ls->carrier_line         = carrier;
    carrier_ls->next_started = true;
    tunnelNextUpStreamInit(t, carrier);
}

void vlessclientCloseLine(tunnel_t *t, line_t *l, vlessclient_close_origin_t origin)
{
    vlessclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVlessClientPhaseClosed)
        return;
    if (ls->kind == kVlessClientLineKindDirect)
    {
        bool next_started = ls->next_started;
        lineRef(l);
        vlessclientLinestateDestroy(ls);
        if (next_started && origin != kVlessClientCloseFromNext)
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
    vlessclient_lstate_t *carrier_ls   = lineGetState(carrier, t);
    bool                  next_started = carrier_ls->next_started;
    application_ls->carrier_line         = NULL;
    carrier_ls->application_line         = NULL;
    vlessclientLinestateDestroy(application_ls);
    vlessclientLinestateDestroy(carrier_ls);
    if (next_started && (from_application || origin != kVlessClientCloseFromNext))
        tunnelNextUpStreamFinish(t, carrier);
    if (lineIsAlive(carrier))
        lineDestroy(carrier);
    if (lineIsAlive(application) && (! from_application || origin != kVlessClientCloseFromPrev))
        tunnelPrevDownStreamFinish(t, application);
    lineUnref(carrier);
    lineUnref(application);
}
