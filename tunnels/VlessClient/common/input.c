#include "internal.h"
#include "loggers/network_logger.h"

static sbuf_t *receiveHead(vlessclient_lstate_t *ls)
{
    if (ls->receive_head == NULL)
        ls->receive_head = bufferqueuePopFront(&ls->pending_down);
    return ls->receive_head;
}

static void recycleEmptyHead(vlessclient_lstate_t *ls)
{
    assert(ls->receive_head != NULL);
    if (sbufGetLength(ls->receive_head) == 0)
    {
        lineReuseBuffer(ls->line, ls->receive_head);
        ls->receive_head = NULL;
    }
}

/* Cached metadata remains charged until its complete header is consumed.
 * Only an owned popped head can change; queued entries stay immutable. */
static bool gatherHeader(vlessclient_lstate_t *ls)
{
    while (ls->header_filled < ls->header_needed)
    {
        sbuf_t *head = receiveHead(ls);
        if (head == NULL)
            return false;
        uint32_t count = min(ls->header_needed - ls->header_filled, sbufGetLength(head));
        sbufReadRangeToMemory(head, ls->header + ls->header_filled, count);
        ls->header_filled += count;
        recycleEmptyHead(ls);
    }
    return true;
}

/* 0 incomplete, -1 malformed, 1 ready. Never consume a byte of TCP body or
 * the first UDP frame as response metadata, including coalesced pipe input. */
int vlessclientReadResponse(vlessclient_lstate_t *ls)
{
    if (! gatherHeader(ls))
        return 0;
    if (UNLIKELY(ls->header[0] != 0))
    {
        LOGE("VlessClient: invalid response header version=%u", (unsigned) ls->header[0]);
        return -1;
    }
    ls->header_needed = kVlessClientResponseLen + ls->header[1];
    if (! gatherHeader(ls))
        return 0;
    if (ls->header[1] != 0)
        LOGW("VlessClient: accepting response header with non-empty addons (len=%u)", (unsigned) ls->header[1]);
    ls->receive_bytes -= ls->header_needed;
    ls->header_filled     = 0;
    ls->header_needed     = kVlessClientUdpHeaderLen;
    ls->response_complete = true;
    return 1;
}

bool vlessclientReadUdpHeader(vlessclient_lstate_t *ls)
{
    if (! gatherHeader(ls))
        return false;
    ls->body_length = ((uint16_t) ls->header[0] << 8U) | ls->header[1];
    return true;
}

sbuf_t *vlessclientTakeTcpBody(vlessclient_lstate_t *ls)
{
    sbuf_t *body = receiveHead(ls);
    if (body != NULL)
    {
        ls->receive_head = NULL;
        ls->receive_bytes -= sbufGetLength(body);
    }
    return body;
}

sbuf_t *vlessclientExtractUdpBody(vlessclient_lstate_t *ls)
{
    uint32_t bytes  = ls->body_length;
    sbuf_t  *result = bufferRangeTakeExact(lineGetBufferPool(ls->line), &ls->receive_head, &ls->pending_down, bytes);
    ls->receive_bytes -= ls->header_needed + bytes;
    ls->header_needed = kVlessClientUdpHeaderLen;
    ls->header_filled = 0;
    ls->body_length   = 0;
    return result;
}
