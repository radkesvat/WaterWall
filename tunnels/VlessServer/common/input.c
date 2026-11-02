#include "internal.h"

/* Cached metadata remains charged until its complete header is consumed.
 * Only an owned popped head can change; queued entries stay immutable. */
bool vlessserverGatherHeader(vlessserver_lstate_t *ls, uint16_t needed)
{
    return bufferreaderGather(&ls->reader, needed);
}

sbuf_t *vlessserverExtractUdpBody(vlessserver_lstate_t *ls, uint16_t bytes)
{
    return bufferreaderTakeBody(&ls->reader, bytes);
}

bool vlessserverDrainInput(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls, bool reject_short_uuid)
{
    if (ls->phase == kVlessServerPhaseWaitInitial)
    {
        if (! vlessserverHandleInitialRequest(t, l, ls, reject_short_uuid))
            return false;
    }

    if (ls->phase == kVlessServerPhaseUdpConnecting || ls->phase == kVlessServerPhaseUdpEstablished)
    {
        return vlessserverDrainUdpPackets(t, l, ls);
    }

    return true;
}
