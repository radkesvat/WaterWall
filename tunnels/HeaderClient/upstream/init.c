#include "structure.h"

#include "loggers/network_logger.h"

void headerclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    const headerclient_tstate_t *ts   = tunnelGetState(t);
    address_context_t           *dest = lineGetDestinationAddressContext(l);
    // Destination-protocol mode records the incoming choice before switching to its TCP carrier.
    const uint8_t allowed  = ts->data_mode == kHeaderClientDataModeDestinationProtocol ? kAddressContextTransportBoth
                                                                                       : kAddressContextTransportTcp;
    const uint8_t incoming = addresscontextSelectTransport(dest, allowed);
    if (incoming == 0)
    {
        tunnelLogTransportRefusal(t, dest, allowed);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    // The receiver of Init can rewrite the mark or protocol and deliver the first payload synchronously.
    switch (ts->data_mode)
    {
    case kHeaderClientDataModeSourceProtocol: {
        const address_context_t          *source   = lineGetSourceAddressContext(l);
        const address_context_transport_t observed = addresscontextClassifyTransport(source);
        if (observed != kAddressContextTransportTcp && observed != kAddressContextTransportUdp)
        {
            tunnelLogTransportRequirement(
                t, source, "an exact TCP or UDP source for settings.data=src_context->protocol");
            tunnelPrevDownStreamFinish(t, l);
            return;
        }
        headerclient_lstate_t *ls = lineGetState(l, t);
        ls->protocol              = observed == kAddressContextTransportTcp ? IP_PROTO_TCP : IP_PROTO_UDP;
        break;
    }
    case kHeaderClientDataModeDestinationProtocol: {
        headerclient_lstate_t *ls = lineGetState(l, t);
        ls->protocol              = incoming == kAddressContextTransportTcp ? IP_PROTO_TCP : IP_PROTO_UDP;
        break;
    }
    case kHeaderClientDataModeLineMark: {
        if (ts->has_configured_mark)
            lineSetMark(l, &ts->configured_mark);
        const line_mark_t *mark = lineGetMark(l);
        if (mark == NULL)
        {
            LOGW("HeaderClient: line has no mark. Set settings.mark or mark the line before HeaderClient");
            tunnelPrevDownStreamFinish(t, l);
            return;
        }
        headerclient_lstate_t *ls = lineGetState(l, t);
        ls->mark                  = *mark;
        break;
    }
    default:
        break;
    }

    addresscontextSetTransportOffer(dest, kAddressContextTransportTcp);
    tunnelNextUpStreamInit(t, l);
}
