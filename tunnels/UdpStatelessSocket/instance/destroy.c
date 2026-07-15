#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelDestroy(tunnel_t *t)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    if (state->socket.idle_tables != NULL)
    {
        for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
        {
            if (state->socket.idle_tables[wid] != NULL)
            {
                LOGF("UdpStatelessSocket: destroying with active worker-local idle table for worker %u",
                     (unsigned int) wid);
                terminateProgram(1);
            }
        }
        memoryFree(state->socket.idle_tables);
        state->socket.idle_tables = NULL;
    }

    if (state->send_request_pools != NULL)
    {
        for (wid_t wid = 0; wid < getTotalWorkersCount(); ++wid)
        {
            threadsafegenericpoolDestroy(state->send_request_pools[wid]);
        }
        memoryFree(state->send_request_pools);
        state->send_request_pools = NULL;
    }

    if (state->send_request_master_pool != NULL)
    {
        masterpoolMakeEmpty(state->send_request_master_pool);
        masterpoolDestroy(state->send_request_master_pool);
        state->send_request_master_pool = NULL;
    }

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
