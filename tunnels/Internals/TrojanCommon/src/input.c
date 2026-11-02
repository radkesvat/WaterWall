#include "TrojanCommon/input.h"

socks_address_result_t trojanGatherAddress(buffer_reader_t *reader, uint16_t base, uint16_t trailer,
                                           socks_address_t *target)
{
    assert((size_t) base + kSocksAddressMaxEncoded + trailer <= UINT16_MAX);
    if (! bufferreaderGather(reader, base + 1))
        return kSocksAddressNeedMore;
    const uint8_t *header = bufferreaderHeader(reader);
    uint16_t       length;
    switch (header[base])
    {
    case kSocksAddressIpv4:
        length = 7;
        break;
    case kSocksAddressIpv6:
        length = 19;
        break;
    case kSocksAddressDomain:
        if (! bufferreaderGather(reader, base + 2))
            return kSocksAddressNeedMore;
        if (header[base + 1] == 0)
            return kSocksAddressInvalid;
        length = 4U + header[base + 1];
        break;
    default:
        return kSocksAddressInvalid;
    }
    if (! bufferreaderGather(reader, base + length + trailer))
        return kSocksAddressNeedMore;
    return target == NULL ? kSocksAddressComplete : socksAddressDecode(header + base, length, target);
}

socks_address_result_t trojanReadUdpHeader(buffer_reader_t *reader, uint16_t *body_length)
{
    const socks_address_result_t result = trojanGatherAddress(reader, 0, 4, NULL);
    if (result != kSocksAddressComplete)
        return result;
    const uint8_t *header = bufferreaderHeader(reader);
    const uint16_t n      = bufferreaderHeaderLength(reader);
    if ((header[n - 6] == 0 && header[n - 5] == 0) || header[n - 2] != '\r' || header[n - 1] != '\n')
        return kSocksAddressInvalid;
    *body_length = ((uint16_t) header[n - 4] << 8U) | header[n - 3];
    return kSocksAddressComplete;
}
