/*
 * TcpOverUdpClient impossible-MTU invariant fixture.
 *
 * Tunnel creation validates that the effective KCP MTU clears ikcp_setmtu()'s own minimum, so a runtime rejection
 * can only mean the validated tunnel state was corrupted afterwards. This fixture reproduces exactly that: it
 * builds a normal tunnel state and then lowers the global MTU behind its back.
 *
 * The allocation-failure branch of ikcp_setmtu() (-2) is deliberately NOT exercised here; it is a per-line failure
 * and is covered by the Category-C failure-injection test instead.
 */
#include "TcpOverUdpClient/structure.h"

#include "tunnels_abort_runtime_cases.h"

int tunnelsAbortTcpOverUdpClientMtuCase(void)
{
    tunnel_t *t = tunnelCreate(NULL, sizeof(tcpoverudpclient_tstate_t), sizeof(tcpoverudpclient_lstate_t));
    if (t == NULL)
    {
        return kAbortCaseAllocationFailed;
    }

    tcpoverudpclient_tstate_t *ts = tunnelGetState(t);

    ts->fec_enabled     = false;
    ts->kcp_nodelay     = true;
    ts->kcp_interval_ms = kTcpOverUdpClientKcpIntervalDefault;
    ts->kcp_resend      = kTcpOverUdpClientKcpResendDefault;
    ts->kcp_send_window = kTcpOverUdpClientKcpSendWindowDefault;
    ts->kcp_recv_window = kTcpOverUdpClientKcpRecvWindowDefault;

    // Below kTcpOverUdpClientKcpMinimumMtu, which tcpoverudpclientTunnelCreate() would have rejected.
    GLOBAL_MTU_SIZE = 10;

    line_t *l = memoryAllocateCacheAlignedZero(sizeof(line_t) + t->lstate_size);
    if (l == NULL)
    {
        return kAbortCaseAllocationFailed;
    }
    atomic_init(&l->refc, 1);
    l->alive = true;
    l->wid   = 0;

    discard tcpoverudpclientLinestateInitialize(lineGetState(l, t), l, t);

    memoryFreeAligned(l);
    return 0;
}
