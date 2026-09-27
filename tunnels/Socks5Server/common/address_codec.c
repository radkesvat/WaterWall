#include "address_codec.h"

#include <assert.h>
#include <string.h>

size_t socks5AddressEncodedLength(const socks5_address_t *address)
{
    assert(address != NULL);
    switch (address->kind)
    {
    case kSocks5AddressIpv4:
        return address->length == 4 ? 7 : 0;
    case kSocks5AddressIpv6:
        return address->length == 16 ? 19 : 0;
    case kSocks5AddressDomain:
        return address->length > 0 && address->length <= UINT8_MAX ? address->length + 4 : 0;
    default:
        return 0;
    }
}

socks5_address_result_t socks5AddressDecode(const uint8_t *wire, size_t length, socks5_address_t *out)
{
    assert(out != NULL && (wire != NULL || length == 0));
    if (length == 0)
        return kSocks5AddressNeedMore;
    socks5_address_t value  = {.kind = wire[0]};
    size_t           offset = 1;
    switch (value.kind)
    {
    case kSocks5AddressIpv4:
        value.length = 4;
        break;
    case kSocks5AddressIpv6:
        value.length = 16;
        break;
    case kSocks5AddressDomain:
        if (length < 2)
            return kSocks5AddressNeedMore;
        value.length = wire[1];
        if (value.length == 0)
            return kSocks5AddressInvalid;
        offset = 2;
        break;
    default:
        return kSocks5AddressInvalid;
    }
    const size_t required = offset + value.length + 2;
    if (length < required)
        return kSocks5AddressNeedMore;
    memcpy(value.bytes, wire + offset, value.length);
    value.port     = (uint16_t) (((uint16_t) wire[required - 2] << 8) | wire[required - 1]);
    value.consumed = required;
    *out           = value;
    return kSocks5AddressComplete;
}

bool socks5AddressEncode(const socks5_address_t *address, uint8_t *wire, size_t capacity, size_t *written)
{
    assert(address != NULL && written != NULL && (wire != NULL || capacity == 0));
    const size_t length = socks5AddressEncodedLength(address);
    if (length == 0 || capacity < length)
        return false;
    size_t offset  = 0;
    wire[offset++] = address->kind;
    if (address->kind == kSocks5AddressDomain)
        wire[offset++] = (uint8_t) address->length;
    memcpy(wire + offset, address->bytes, address->length);
    wire[length - 2] = (uint8_t) (address->port >> 8);
    wire[length - 1] = (uint8_t) address->port;
    *written         = length;
    return true;
}
