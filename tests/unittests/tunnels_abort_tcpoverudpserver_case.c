/*
 * TcpOverUdpServer impossible-MTU invariant fixture.
 *
 * Mirror of the TcpOverUdpClient case; the two implementations must stay behaviorally symmetric.
 */
#include "TcpOverUdpServer/structure.h"

#include "tunnels_abort_runtime_cases.h"

int tunnelsAbortTcpOverUdpServerMtuCase(void)
{
    tunnel_t *t = tunnelCreate(NULL, sizeof(tcpoverudpserver_tstate_t), sizeof(tcpoverudpserver_lstate_t));
    if (t == NULL)
    {
        return kAbortCaseAllocationFailed;
    }

    tcpoverudpserver_tstate_t *ts = tunnelGetState(t);

    ts->fec_enabled     = false;
    ts->kcp_nodelay     = true;
    ts->kcp_interval_ms = kTcpOverUdpServerKcpIntervalDefault;
    ts->kcp_resend      = kTcpOverUdpServerKcpResendDefault;
    ts->kcp_send_window = kTcpOverUdpServerKcpSendWindowDefault;
    ts->kcp_recv_window = kTcpOverUdpServerKcpRecvWindowDefault;

    // Below kTcpOverUdpServerKcpMinimumMtu, which tcpoverudpserverTunnelCreate() would have rejected.
    GLOBAL_MTU_SIZE = 10;

    line_t *l = memoryAllocateCacheAlignedZero(sizeof(line_t) + t->lstate_size);
    if (l == NULL)
    {
        return kAbortCaseAllocationFailed;
    }
    atomic_init(&l->refc, 1);
    l->alive = true;
    l->wid   = 0;

    discard tcpoverudpserverLinestateInitialize(lineGetState(l, t), l, t);

    memoryFreeAligned(l);
    return 0;
}
