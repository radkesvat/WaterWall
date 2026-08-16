/*
 * UdpStatelessSocket unsafe-destruction fixture.
 *
 * This translation unit sees only UdpStatelessSocket's production structure.h,
 * so the tunnel state is the real udpstatelesssocket_tstate_t at its real size
 * and offsets; nothing here assumes where socket.idle_tables lives.
 */
#include "UdpStatelessSocket/structure.h"

#include "tunnels_abort_runtime_cases.h"

int tunnelsAbortUdpStatelessSocketDestroyCase(void)
{
    const wid_t workers = getWorkersCount();
    if (workers < 1)
    {
        return kAbortCaseInvalidWorkerCount;
    }

    // Mirror tunnelCreate()'s allocation exactly: tunnel_t followed by the
    // aligned tunnel state, on a cache-line boundary.
    const uint32_t tstate_size = tunnelGetCorrectAlignedStateSize(sizeof(udpstatelesssocket_tstate_t));

    tunnel_t *t = memoryAllocateCacheAlignedZero(sizeof(tunnel_t) + (size_t) tstate_size);
    if (t == NULL)
    {
        return kAbortCaseAllocationFailed;
    }
    t->tstate_size = tstate_size;

    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    state->socket.idle_tables = memoryAllocateZero(sizeof(local_idle_table_t *) * (size_t) workers);
    if (state->socket.idle_tables == NULL)
    {
        memoryFreeAligned(t);
        return kAbortCaseAllocationFailed;
    }

    // A worker-local idle table still installed at destroy time is the
    // invariant under test. The production path must log and abort before it
    // frees the table array or touches any later-destroyed state.
    static uint64_t idle_table_sentinel = 0;

    state->socket.idle_tables[0] = (local_idle_table_t *) &idle_table_sentinel;

    udpstatelesssocketTunnelDestroy(t, wwLifecycleStartupRollback());

    return 0;
}
