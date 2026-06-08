#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelDestroy(tunnel_t *t)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    udpstatelesssocket_dns_cache_entry_t *entry = state->dns_cache;
    while (entry != NULL)
    {
        udpstatelesssocket_dns_cache_entry_t *next = entry->next;
        memoryFree(entry->domain);
        memoryFree(entry);
        entry = next;
    }
    mutexDestroy(&state->dns_cache_mutex);

    if (state->listen_address)
    {
        memoryFree(state->listen_address);
    }
    if (state->interface_name)
    {
        memoryFree(state->interface_name);
    }

    tunnelDestroy(t);
}
