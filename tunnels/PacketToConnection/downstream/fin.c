#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    ptc_lstate_t *lstate = lineGetState(l, t);

    bool unlock_core = false;
    if (! lstate->stack_owned_locked && ! lstate->local_locked)
    {
        // we are on a different worker thread, so we must lock the tcpip mutex
        LOCK_TCPIP_CORE();
        assert(lineIsAlive(l));

        unlock_core = true;
    }

    if (lstate->is_closing)
    {
        // ugh ... we have been queued a close event
        // and also being closed by upstream
        // we cannot kill the line here , because other messages need the line state
        
        lineLock(l);
        lineDestroy(l);
       goto return_unlockifneeded;
    }

    // This indicates that line is closed. Even if we get the closeCallback
    // while flushing the queue, no FIN will be sent to upstream
    assert(lstate->messages == 0);

    // try if we can write anything left
    ptcFlushWriteQueue(lstate);

    tcp_close(lstate->tcp_pcb);
    lstate->is_closing            = true;
    lstate->tcp_pcb->callback_arg = NULL;
    lstate->tcp_pcb               = NULL;

    ptcLinestateDestroy(lstate);
    lineDestroy(l);

return_unlockifneeded:
    if (unlock_core)
    {
        UNLOCK_TCPIP_CORE();
    }
}
