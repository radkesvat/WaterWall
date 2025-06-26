#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    (void) l;
    // discard t;
    rawsocket_tstate_t *state = tunnelGetState(t);

    // printIPPacketInfo("RawSocket sending: ", sbufGetRawPtr(buf));
    struct ip_hdr *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);

    if (l->recalculate_checksum)
    {
        IPH_CHKSUM_SET(ipheader, 0);
        IPH_CHKSUM_SET(ipheader, inet_chksum(ipheader, IPH_HL_BYTES(ipheader)));
        l->recalculate_checksum = false;
    }

    if (! writeToRawDevce(state->raw_device, buf))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);
    }
}
