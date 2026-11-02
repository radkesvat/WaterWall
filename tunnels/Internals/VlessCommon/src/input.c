#include "VlessCommon/input.h"

bool vlessReadUdpHeader(buffer_reader_t *reader, uint16_t *body_length)
{
    if (! bufferreaderGather(reader, kVlessUdpHeaderLen))
        return false;
    const uint8_t *header = bufferreaderHeader(reader);
    *body_length          = ((uint16_t) header[0] << 8U) | header[1];
    return true;
}
