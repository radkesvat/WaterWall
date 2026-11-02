#include "internal.h"

#include "TrojanCommon/input.h"

/* 0: incomplete, 1: header validated, -1: malformed. */
int trojanclientReadUdpHeader(trojanclient_lstate_t *ls)
{
    if (! ls->header_ready)
    {
        const socks_address_result_t result = trojanReadUdpHeader(&ls->reader, &ls->body_length);
        if (result != kSocksAddressComplete)
            return result;
        ls->header_ready = true;
    }
    return 1;
}

sbuf_t *trojanclientExtractUdpBody(trojanclient_lstate_t *ls)
{
    sbuf_t *result   = bufferreaderTakeBody(&ls->reader, ls->body_length);
    ls->header_ready = false;
    ls->body_length  = 0;
    return result;
}
