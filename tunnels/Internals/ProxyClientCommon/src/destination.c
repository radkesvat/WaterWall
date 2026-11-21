#include "ProxyClientCommon/destination.h"

#include "loggers/network_logger.h"
#include "objects/node.h"

bool proxyClientApplyDestination(tunnel_t *client, address_context_t *destination,
                                 const proxy_client_destination_t *selection)
{
    assert(client != NULL && destination != NULL && selection != NULL && selection->target != NULL);
    assert(destination != selection->target);
    assert(selection->protocol == kProxyClientProtocolTcp || selection->protocol == kProxyClientProtocolUdp ||
           selection->protocol == kProxyClientProtocolDestContext);

    const node_t *node        = tunnelGetNode(client);
    const char   *client_name = node != NULL && node->type != NULL ? node->type : "ProxyClient";
    const bool    pinned      = addresscontextDestinationIsPinned(destination);
    if (pinned && (! addresscontextIsValid(destination) || ! addresscontextHasPort(destination)))
    {
        LOGE("%s: pinned destination requires a valid address and port", client_name);
        return false;
    }
    const uint8_t allowed   = pinned || selection->protocol == kProxyClientProtocolDestContext
                                  ? kAddressContextTransportBoth
                              : selection->protocol == kProxyClientProtocolTcp ? kAddressContextTransportTcp
                                                                               : kAddressContextTransportUdp;
    const uint8_t transport = addresscontextSelectTransport(destination, allowed);
    if (transport == 0)
    {
        tunnelLogTransportRefusal(client, destination, allowed);
        return false;
    }

    if (pinned)
    {
        // This proxy encodes the logical endpoint. Its independent outer
        // carrier must still select the configured VPN/proxy server normally.
        addresscontextSetDestinationPinned(destination, false);
        return true;
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
