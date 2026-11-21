#include "structure.h"

#include "loggers/network_logger.h"

void encryptionclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    address_context_t *destination = lineGetDestinationAddressContext(l);
    const uint8_t      transport   = addresscontextSelectTransport(destination, kAddressContextTransportBoth);
    if (transport == 0)
    {
        LOGW("EncryptionClient: line does not offer TCP or UDP");
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    addresscontextSetTransportOffer(destination, transport);
    encryptionclient_lstate_t *ls = lineGetState(l, t);
    encryptionclientLinestateInitialize(ls, lineGetBufferPool(l), transport == kAddressContextTransportUdp);
    tunnelNextUpStreamInit(t, l);
}
