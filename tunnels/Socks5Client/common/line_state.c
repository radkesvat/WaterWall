#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientLinestateInitialize(socks5client_lstate_t *ls, tunnel_t *t, line_t *l)
{
    *ls = (socks5client_lstate_t) {.tunnel      = t,
                                   .line        = l,
                                   .dns_request = NULL,
                                   .in_stream   = bufferstreamCreate(lineGetBufferPool(l), 0),
                                   .pending_up  = bufferqueueCreate(kSocks5ClientPendingQueueCap),
                                   .protocol    = kSocks5ClientProtocolTcp,
                                   .phase       = kSocks5ClientPhaseIdle};
}

void socks5clientCancelDnsRequest(socks5client_lstate_t *ls)
{
    if (ls->dns_request != NULL)
    {
        ls->dns_request->cancelled = true;
        ls->dns_request            = NULL;
    }
}

void socks5clientLinestateDestroy(socks5client_lstate_t *ls)
{
    socks5clientCancelDnsRequest(ls);
    addresscontextReset(&ls->target_addr);
    addresscontextReset(&ls->relay_addr);
    bufferstreamDestroy(&ls->in_stream);
    bufferqueueDestroy(&ls->pending_up);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(socks5client_lstate_t)));
}
