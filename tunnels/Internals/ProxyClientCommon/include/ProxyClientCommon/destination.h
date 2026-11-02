#pragma once

#include "address_context.h"

typedef enum proxy_client_protocol_e
{
    kProxyClientProtocolTcp,
    kProxyClientProtocolUdp,
    kProxyClientProtocolDestContext
} proxy_client_protocol_t;

typedef struct proxy_client_destination_s
{
    const address_context_t *target;
    proxy_client_protocol_t  protocol;
    bool                     address_from_context;
    bool                     port_from_context;
} proxy_client_destination_t;

/* Select address, port and transport before local DNS or direct client Init.
 * target is immutable, distinct from destination and valid for constant fields.
 * Inherited fields come from a snapshot taken before replacing destination.
 * Copies the selected address source's metadata and domain ownership semantics;
 * success leaves exactly TCP or UDP selected. Invalid inherited protocol warns
 * and falls back to TCP. Missing inherited address/port returns false; destination
 * may already have changed. No callbacks, line state or DNS operations. Protocol
 * validation and any DNS-strategy override remain with the client. */
bool proxyClientApplyDestination(address_context_t *destination, const proxy_client_destination_t *selection,
                                 const char *client_name);
