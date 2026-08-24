#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    /* This node has no external producer root. Worker-message and event-loop
     * admission close with the owning workers, and async DNS settles before
     * they publish Quiesced. */
    discard t;
    discard context;
}

void udpstatelesssocketTunnelOnQuiesceWait(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    /* The controller reaches this hook only after every owner worker is
     * Quiesced, so there is no independent callback root left to wait for. */
    discard t;
    discard context;
}

void udpstatelesssocketTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    if (wid == state->io_wid && state->socket.io != NULL)
    {
        wioClose(state->socket.io);
        state->socket.io = NULL;
    }
    assert(state->socket.idle_tables != NULL);
    if (state->socket.idle_tables[wid] != NULL)
    {
        localidletableQuiesce(state->socket.idle_tables[wid]);
    }
}

void udpstatelesssocketTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));

    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    assert(state->socket.idle_tables != NULL);

    local_idle_table_t *table = state->socket.idle_tables[wid];
    if (table == NULL)
    {
        return;
    }

    localidletableDrainItems(table);
    localidletableDestroy(table);
    state->socket.idle_tables[wid] = NULL;
}
