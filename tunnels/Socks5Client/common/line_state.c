#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientLinestateInitialize(socks5client_lstate_t *ls, tunnel_t *t, line_t *l)
{
    *ls = (socks5client_lstate_t) {.tunnel     = t,
                                   .line       = l,
                                   .in_stream  = bufferstreamCreate(lineGetBufferPool(l), 0),
                                   .pending_up = bufferqueueCreate(kSocks5ClientPendingQueueCap),
                                   .protocol   = kSocks5ClientProtocolTcp,
                                   .phase      = kSocks5ClientPhaseIdle};
}

void socks5clientLinestateDestroy(socks5client_lstate_t *ls)
{
    addresscontextReset(&ls->target_addr);
    addresscontextReset(&ls->relay_addr);
    bufferstreamDestroy(&ls->in_stream);
    bufferqueueDestroy(&ls->pending_up);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(socks5client_lstate_t)));
}

void socks5clientDomainSetupLinestateInitialize(socks5client_domain_setup_lstate_t *ls)
{
    *ls = (socks5client_domain_setup_lstate_t) {.protocol = kSocks5ClientProtocolTcp};
}

void socks5clientDomainSetupLinestateDestroy(socks5client_domain_setup_lstate_t *ls)
{
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(socks5client_domain_setup_lstate_t)));
}
