#include "internal.h"

static sbuf_t *receiveHead(trojanclient_lstate_t *ls)
{
    if (ls->receive_head == NULL)
        ls->receive_head = bufferqueuePopFront(&ls->pending_down);
    return ls->receive_head;
}

static void recycleEmptyHead(trojanclient_lstate_t *ls)
{
    if (ls->receive_head != NULL && sbufGetLength(ls->receive_head) == 0)
    {
        lineReuseBuffer(ls->line, ls->receive_head);
        ls->receive_head = NULL;
    }
}

/* 0: incomplete, 1: header validated, -1: malformed. Only required header
 * bytes leave their representation; waiting bodies remain in their pipes. */
int trojanclientReadUdpHeader(trojanclient_lstate_t *ls)
{
    while (! ls->header_ready)
    {
        while (ls->header_filled < ls->header_needed)
        {
            sbuf_t *head = receiveHead(ls);
            if (head == NULL)
                return 0;
            uint32_t count = min(ls->header_needed - ls->header_filled, sbufGetLength(head));
            sbufReadRangeToMemory(head, ls->header + ls->header_filled, count);
            ls->header_filled += count;
            recycleEmptyHead(ls);
        }
        if (ls->header_needed == 1)
        {
            switch (ls->header[0])
            {
            case kTrojanAtypIpv4:
                ls->header_needed = 11;
                break;
            case kTrojanAtypIpv6:
                ls->header_needed = 23;
                break;
            case kTrojanAtypDomain:
                ls->header_needed = 2;
                break;
            default:
                return -1;
            }
        }
        else if (ls->header_needed == 2)
        {
            if (ls->header[1] == 0)
                return -1;
            ls->header_needed = 8U + ls->header[1];
        }
        else
        {
            trojanclient_address_t source;
            bool                   valid =
                trojanclientAddressDecode(ls->header, ls->header_filled, &source) == kTrojanClientAddressComplete &&
                source.port != 0;
            uint16_t n      = ls->header_needed;
            ls->body_length = ((uint16_t) ls->header[n - 4] << 8U) | ls->header[n - 3];
            if (! valid || ls->header[n - 2] != '\r' || ls->header[n - 1] != '\n' ||
                ls->body_length > kTrojanClientUdpMaxPacket)
                return -1;
            ls->header_ready = true;
        }
    }
    return 1;
}

sbuf_t *trojanclientExtractUdpBody(trojanclient_lstate_t *ls)
{
    buffer_pool_t *pool    = lineGetBufferPool(ls->line);
    uint16_t       padding = bufferpoolGetLargeBufferPadding(pool);
    uint32_t       bytes   = ls->body_length;
    sbuf_t        *head    = receiveHead(ls);
    sbuf_t        *result  = NULL;
    if (bytes != 0 && head != NULL && sbufGetLength(head) == bytes && sbufGetLeftCapacity(head) >= padding)
    {
        result           = head;
        ls->receive_head = NULL;
    }
    else
    {
        bool   has_pipe = head != NULL && sbufIsSplice(head);
        size_t range    = head == NULL ? 0 : sbufGetLength(head);
        c_foreach(i, ww_sbuffer_queue_t, ls->pending_down.q)
        {
            if (range >= bytes)
                break;
            has_pipe |= sbufIsSplice(*i.ref);
            range += sbufGetLength(*i.ref);
        }
        if (bytes != 0 && has_pipe)
            result = bufferpoolGetSpliceBuffer(pool);
        if (result != NULL && sbufGetLeftCapacity(result) < padding)
        {
            bufferpoolReuseBuffer(pool, result);
            result = NULL;
        }
        if (result == NULL)
            result = bufferpoolGetBestFit(pool, bytes, padding);
        uint32_t remaining = bytes;
        while (remaining != 0)
        {
            head           = receiveHead(ls);
            uint32_t count = min(remaining, sbufGetLength(head));
            result         = sbufMoveRangeTo(pool, head, result, count, bytes, padding);
            remaining -= count;
            recycleEmptyHead(ls);
        }
    }
    ls->receive_bytes -= ls->header_needed + bytes;
    ls->header_needed = 1;
    ls->header_filled = 0;
    ls->header_ready  = false;
    ls->body_length   = 0;
    return result;
}
