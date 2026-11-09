#include "ProxyClientCommon/destination.h"

#include "loggers/network_logger.h"

static uint8_t selectProtocol(proxy_client_protocol_t protocol, const address_context_t *current,
                              const char *client_name)
{
    if (protocol != kProxyClientProtocolDestContext)
        return protocol == kProxyClientProtocolTcp ? IP_PROTO_TCP : IP_PROTO_UDP;

    const address_context_transport_t transport = addresscontextClassifyTransport(current);
    if (transport == kAddressContextTransportTcp)
        return IP_PROTO_TCP;
    if (transport == kAddressContextTransportUdp)
        return IP_PROTO_UDP;

    LOGW("%s: configured protocol is dest_context->protocol, but the destination context protocol was "
         "missing or invalid (tcp=%u, udp=%u, icmp=%u, packet=%u); falling back to TCP",
         client_name,
         (unsigned int) current->proto_tcp,
         (unsigned int) current->proto_udp,
         (unsigned int) current->proto_icmp,
         (unsigned int) current->proto_packet);
    return IP_PROTO_TCP;
}

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

    address_context_t current = {0};
    if (selection->address_from_context || selection->port_from_context ||
        selection->protocol == kProxyClientProtocolDestContext)
        addresscontextCopy(&current, destination);

    const uint8_t protocol = selectProtocol(selection->protocol, &current, client_name);
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

    addresscontextSetOnlyProtocol(destination, protocol);
    addresscontextReset(&current);
    return true;
}
