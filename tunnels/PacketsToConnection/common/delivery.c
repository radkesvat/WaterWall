#include "structure.h"

#include "loggers/network_logger.h"

bool ptcEnsureNextInit(tunnel_t *t, line_t *l, ptc_lstate_t *ls)
{
    if (ls->next_init_sent)
    {
        return true;
    }

    ls->next_init_sent = true;
    return lineCallWithRef(l, tunnelNextUpStreamInit, t);
}

void ptcOpenLineTask(tunnel_t *t, line_t *l)
{
    if (! ptcNextGateEnter(t))
    {
        ptcCloseLineForStop(t, l);
        return;
    }

    ptc_lstate_t *ls = lineGetState(l, t);

    if (! ptcEnsureNextInit(t, l, ls))
    {
        ptcNextGateLeave(t);
        return;
    }

    ls = lineGetState(l, t);
    if (ls->kind == kPtcLineKindUdp && ! ptcArmUdpIdleOnOwnerThread(ls))
    {
        ptcCloseLineFromNetwork(t, l);
    }
    ptcNextGateLeave(t);
}

void ptcDeliverPayloadTask(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    buffer_pool_t *pool = lineGetBufferPool(l);

    if (! ptcNextGateEnter(t))
    {
        bufferpoolReuseBuffer(pool, buf);
        ptcCloseLineForStop(t, l);
        return;
    }

    ptc_lstate_t *ls       = lineGetState(l, t);
    uint32_t      tcp_read = sbufGetLength(buf);

    if (! ptcEnsureNextInit(t, l, ls))
    {
        bufferpoolReuseBuffer(pool, buf);
        ptcNextGateLeave(t);
        return;
    }

    ls = lineGetState(l, t);

    if (ls->kind == kPtcLineKindUdp)
    {
        if (! ptcArmUdpIdleOnOwnerThread(ls))
        {
            bufferpoolReuseBuffer(pool, buf);
            ptcCloseLineFromNetwork(t, l);
            ptcNextGateLeave(t);
            return;
        }
        if (ls->read_paused)
        {
            lineReuseBuffer(l, buf);
            ptcNextGateLeave(t);
            return;
        }
    }

    if (! lineCallWithRefWithBuf(l, tunnelNextUpStreamPayload, t, buf))
    {
        ptcNextGateLeave(t);
        return;
    }

    ls = lineGetState(l, t);

    if (ls->kind == kPtcLineKindTcp)
    {
        if (ls->read_paused)
        {
            ww_lwip_engine_t *previous;
            const bool        entered = wwLwipEngineEnter(ls->engine, &previous);
            assert(entered);
            discard    entered;
            const bool accumulated = ptcPausedReadAccumulateLocked(ls, tcp_read);
            wwLwipEngineLeave(ls->engine, previous);
            ptcNextGateLeave(t);
            discard accumulated;
            return;
        }

        ww_lwip_engine_t *previous;
        const bool        entered = wwLwipEngineEnter(ls->engine, &previous);
        assert(entered);
        discard entered;
        discard ptcReturnReceiveCreditLocked(ls, tcp_read);
        wwLwipEngineLeave(ls->engine, previous);
    }
    ptcNextGateLeave(t);
}

void ptcCloseLineTask(tunnel_t *t, line_t *l)
{
    if (! ptcNextGateEnter(t))
    {
        ptcCloseLineForStop(t, l);
        return;
    }
    ptcCloseLineFromNetwork(t, l);
    ptcNextGateLeave(t);
}

void ptcResumeUpstreamTask(tunnel_t *t, line_t *l)
{
    if (! ptcNextGateEnter(t))
    {
        ptcCloseLineForStop(t, l);
        return;
    }
    const ptc_lstate_t *ls = lineGetState(l, t);
    if (! ls->write_paused)
        discard lineCallWithRef(l, tunnelNextUpStreamResume, t);
    ptcNextGateLeave(t);
}
