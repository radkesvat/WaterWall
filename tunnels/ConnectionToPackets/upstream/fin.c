#include "structure.h"

#include "loggers/network_logger.h"

void ctpTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    if (UNLIKELY(ctpLineIsPacketLine(t, l)))
    {
        LOGF("ConnectionToPackets: unexpected upstream Finish on the packet line");
        abortProgramNow(1);
        return;
    }

    ctp_lstate_t *ls = lineGetState(l, t);

    if (ls->tunnel == NULL)
    {
        // A network-originated close already released this state and reported it.
        return;
    }

    /*
     * prev is the sender of this Finish, so nothing may travel back toward it.
     * The normal line is never forwarded to next either, so there is no onward
     * direction to propagate into: detaching from lwIP and releasing this node's
     * own state is the whole job. Destroying that state is also what tells every
     * other close path that prev is gone, so no directional-close flag is kept.
     * The line is borrowed - prev created it and prev destroys it - so
     * lineDestroy() is never called here.
     */
    if (ls->engine != NULL)
    {
        ww_lwip_engine_t *previous;
        const bool        entered = wwLwipEngineEnter(ls->engine, &previous);
        assert(entered);
        discard entered;
        ctpDetachFlowLocked(t, ls, true);
        wwLwipEngineLeave(ls->engine, previous);
    }

    ctpLinestateDestroy(ls);
}
