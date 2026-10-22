#include "structure.h"

#include "loggers/network_logger.h"

void headerclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    const headerclient_tstate_t *ts        = tunnelGetState(t);
    headerclient_lstate_t       *ls        = lineGetState(l, t);
    const address_context_t     *ctx       = ts->data_mode == kHeaderClientDataModeSourceProtocol
                                                 ? lineGetSourceAddressContext(l)
                                                 : lineGetDestinationAddressContext(l);
    address_context_transport_t  transport = addresscontextClassifyTransport(ctx);

    *ls = (headerclient_lstate_t) {0};
    if (transport != kAddressContextTransportTcp && transport != kAddressContextTransportUdp)
    {
        LOGE("HeaderClient: selected context must specify exactly TCP or UDP");
        headerclientLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    /* The next adapter may replace the context with its carrier transport. */
    ls->protocol = transport == kAddressContextTransportTcp ? IP_PROTO_TCP : IP_PROTO_UDP;
    tunnelNextUpStreamInit(t, l);
}
