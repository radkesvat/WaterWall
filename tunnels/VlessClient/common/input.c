#include "internal.h"
#include "loggers/network_logger.h"

/* 0 incomplete, -1 malformed, 1 ready. Never consume a byte of TCP body or
 * the first UDP frame as response metadata, including coalesced pipe input. */
int vlessclientReadResponse(vlessclient_lstate_t *ls)
{
    if (! bufferreaderGather(&ls->reader, kVlessClientResponseLen))
        return 0;
    if (UNLIKELY(ls->header[0] != 0))
    {
        LOGE("VlessClient: invalid response header version=%u", (unsigned) ls->header[0]);
        return -1;
    }
    if (! bufferreaderGather(&ls->reader, kVlessClientResponseLen + ls->header[1]))
        return 0;
    if (ls->header[1] != 0)
        LOGW("VlessClient: accepting response header with non-empty addons (len=%u)", (unsigned) ls->header[1]);
    bufferreaderConsumeHeader(&ls->reader);
    ls->response_complete = true;
    return 1;
}

bool vlessclientReadUdpHeader(vlessclient_lstate_t *ls)
{
    return vlessReadUdpHeader(&ls->reader, &ls->body_length);
}

sbuf_t *vlessclientTakeTcpBody(vlessclient_lstate_t *ls)
{
    return bufferreaderTakeChunk(&ls->reader);
}

sbuf_t *vlessclientExtractUdpBody(vlessclient_lstate_t *ls)
{
    sbuf_t *result    = bufferreaderTakeBody(&ls->reader, ls->body_length);
    ls->body_length   = 0;
    return result;
}
