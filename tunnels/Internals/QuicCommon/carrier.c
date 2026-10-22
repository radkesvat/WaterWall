#include "carrier.h"
#include "quic_engine.h"

#include <assert.h>
#include <string.h>

void ww_quic_carrier_header(uint8_t header[4], uint32_t length)
{
    assert(length > 0 && length <= WW_QUIC_MAX_DATAGRAM);
    header[0] = (uint8_t) (length >> 24);
    header[1] = (uint8_t) (length >> 16);
    header[2] = (uint8_t) (length >> 8);
    header[3] = (uint8_t) length;
}

size_t ww_quic_carrier_retained(const ww_quic_carrier_t *carrier)
{
    return carrier->header_used + carrier->body_used;
}

void ww_quic_carrier_release_packet(ww_quic_carrier_t *carrier)
{
    if (carrier->body != NULL)
    {
        carrier->deallocate(carrier->context, carrier->body, carrier->body_length);
    }
    carrier->body        = NULL;
    carrier->header_used = 0;
    carrier->body_length = 0;
    carrier->body_used   = 0;
}

void ww_quic_carrier_destroy(ww_quic_carrier_t *carrier)
{
    ww_quic_carrier_release_packet(carrier);
}

ww_quic_carrier_result_t ww_quic_carrier_decode(ww_quic_carrier_t *carrier, const uint8_t *input, size_t length,
                                                size_t *consumed, const uint8_t **packet, size_t *packet_length)
{
    assert(carrier != NULL && consumed != NULL && packet != NULL && packet_length != NULL);
    assert(carrier->allocate != NULL && carrier->deallocate != NULL);
    *consumed      = 0;
    *packet        = NULL;
    *packet_length = 0;
    while (carrier->header_used < 4 && *consumed < length)
    {
        carrier->header[carrier->header_used++] = input[(*consumed)++];
    }
    if (carrier->header_used < 4)
    {
        return WW_QUIC_CARRIER_MORE;
    }
    if (carrier->body_length == 0)
    {
        carrier->body_length = ((uint32_t) carrier->header[0] << 24) | ((uint32_t) carrier->header[1] << 16) |
                               ((uint32_t) carrier->header[2] << 8) | carrier->header[3];
        if (carrier->body_length == 0 || carrier->body_length > WW_QUIC_MAX_DATAGRAM)
        {
            return WW_QUIC_CARRIER_INVALID;
        }
    }
    size_t available = length - *consumed;
    size_t needed    = carrier->body_length - carrier->body_used;
    if (carrier->body == NULL && available >= needed)
    {
        *packet        = input + *consumed;
        *packet_length = needed;
        *consumed += needed;
        return WW_QUIC_CARRIER_PACKET;
    }
    if (available == 0)
    {
        return WW_QUIC_CARRIER_MORE;
    }
    if (carrier->body == NULL)
    {
        carrier->body = carrier->allocate(carrier->context, carrier->body_length);
        if (carrier->body == NULL)
        {
            return WW_QUIC_CARRIER_REFUSED;
        }
    }
    size_t copied = available < needed ? available : needed;
    memcpy(carrier->body + carrier->body_used, input + *consumed, copied);
    carrier->body_used += (uint32_t) copied;
    *consumed += copied;
    if (carrier->body_used < carrier->body_length)
    {
        return WW_QUIC_CARRIER_MORE;
    }
    *packet        = carrier->body;
    *packet_length = carrier->body_length;
    return WW_QUIC_CARRIER_PACKET;
}
