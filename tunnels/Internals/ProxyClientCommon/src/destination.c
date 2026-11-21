#include "ProxyClientCommon/destination.h"

#include "loggers/network_logger.h"

bool proxyClientApplyDestination(address_context_t *destination, const proxy_client_destination_t *selection,
                                 const char *client_name)
{
    assert(destination != NULL && selection != NULL && selection->target != NULL && client_name != NULL);
    assert(destination != selection->target);
    assert(selection->protocol == kProxyClientProtocolTcp || selection->protocol == kProxyClientProtocolUdp ||
           selection->protocol == kProxyClientProtocolDestContext);

    if (addresscontextDestinationIsPinned(destination))
    {
        const address_context_transport_t transport = addresscontextClassifyTransport(destination);
        if (! addresscontextIsValid(destination) || ! addresscontextHasPort(destination) ||
            (transport != kAddressContextTransportTcp && transport != kAddressContextTransportUdp))
        {
            LOGE("%s: pinned destination requires an address, port and exact TCP or UDP transport", client_name);
            return false;
        }
        // This proxy encodes the logical endpoint. Its independent outer
        // carrier must still select the configured VPN/proxy server normally.
        addresscontextSetDestinationPinned(destination, false);
        return true;
    }

    const uint8_t allowed   = selection->protocol == kProxyClientProtocolTcp   ? kAddressContextTransportTcp
                              : selection->protocol == kProxyClientProtocolUdp ? kAddressContextTransportUdp
                                                                               : kAddressContextTransportBoth;
    const uint8_t transport = addresscontextSelectTransport(destination, allowed);
    if (transport == 0)
    {
        LOGW("%s: destination offers no transport permitted by the configured protocol", client_name);
        return false;
    }

    address_context_t current = {0};
    if (selection->address_from_context || selection->port_from_context)
        addresscontextCopy(&current, destination);

    if (selection->address_from_context)
    {
        if (UNLIKELY(! addresscontextIsValid(&current)))
        {
            LOGE("%s: configured to use dest_context->address, but line destination address is not set", client_name);
            addresscontextReset(&current);
            return false;
        }
        addresscontextCopy(destination, &current);
    }
    else
        addresscontextCopy(destination, selection->target);

    if (selection->port_from_context)
    {
        if (UNLIKELY(current.port == 0))
        {
            LOGE("%s: configured to use dest_context->port, but line destination port is not set", client_name);
            addresscontextReset(&current);
            return false;
        }
        addresscontextSetPort(destination, current.port);
    }
    else
        addresscontextSetPort(destination, selection->target->port);

    addresscontextSetTransportOffer(destination, transport);
    addresscontextReset(&current);
    return true;
}
