#include "buffer_queue_range.h"
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
            /* Address kind and extent were validated while gathering the header.
             * Only its port is needed here; the reply never retargets the application. */
            uint16_t n        = ls->header_needed;
            bool     has_port = ls->header[n - 6] != 0 || ls->header[n - 5] != 0;
            ls->body_length   = ((uint16_t) ls->header[n - 4] << 8U) | ls->header[n - 3];
            if (! has_port || ls->header[n - 2] != '\r' || ls->header[n - 1] != '\n')
                return -1;
            ls->header_ready = true;
        }
    }
    return 1;
}

sbuf_t *trojanclientExtractUdpBody(trojanclient_lstate_t *ls)
{
    uint32_t bytes  = ls->body_length;
    sbuf_t  *result = bufferRangeTakeExact(lineGetBufferPool(ls->line), &ls->receive_head, &ls->pending_down, bytes);
    ls->receive_bytes -= ls->header_needed + bytes;
    ls->header_needed = 1;
    ls->header_filled = 0;
    ls->header_ready  = false;
    ls->body_length   = 0;
    return result;
}
