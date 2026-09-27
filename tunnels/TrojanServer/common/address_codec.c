#include "address_codec.h"

#include <assert.h>
#include <string.h>

size_t trojanserverAddressEncodedLength(const trojanserver_address_t *address)
{
    assert(address != NULL);
    switch (address->kind)
    {
    case kTrojanServerAddressIpv4:
        return address->length == 4 ? 7 : 0;
    case kTrojanServerAddressIpv6:
        return address->length == 16 ? 19 : 0;
    case kTrojanServerAddressDomain:
        return address->length > 0 && address->length <= UINT8_MAX ? address->length + 4 : 0;
    default:
        return 0;
    }
}

trojanserver_address_result_t trojanserverAddressDecode(const uint8_t *wire, size_t length, trojanserver_address_t *out)
{
    assert(out != NULL && (wire != NULL || length == 0));
    if (length == 0)
        return kTrojanServerAddressNeedMore;
    trojanserver_address_t value  = {.kind = wire[0]};
    size_t                 offset = 1;
    switch (value.kind)
    {
    case kTrojanServerAddressIpv4:
        value.length = 4;
        break;
    case kTrojanServerAddressIpv6:
        value.length = 16;
        break;
    case kTrojanServerAddressDomain:
        if (length < 2)
            return kTrojanServerAddressNeedMore;
        value.length = wire[1];
        if (value.length == 0)
            return kTrojanServerAddressInvalid;
        offset = 2;
        break;
    default:
        return kTrojanServerAddressInvalid;
    }
    const size_t required = offset + value.length + 2;
    if (length < required)
        return kTrojanServerAddressNeedMore;
    memcpy(value.bytes, wire + offset, value.length);
    value.port     = (uint16_t) (((uint16_t) wire[required - 2] << 8) | wire[required - 1]);
    value.consumed = required;
    *out           = value;
    return kTrojanServerAddressComplete;
}

bool trojanserverAddressEncode(const trojanserver_address_t *address, uint8_t *wire, size_t capacity, size_t *written)
{
    assert(address != NULL && written != NULL && (wire != NULL || capacity == 0));
    const size_t length = trojanserverAddressEncodedLength(address);
    if (length == 0 || capacity < length)
        return false;
    size_t offset  = 0;
    wire[offset++] = address->kind;
    if (address->kind == kTrojanServerAddressDomain)
        wire[offset++] = (uint8_t) address->length;
    memcpy(wire + offset, address->bytes, address->length);
    wire[length - 2] = (uint8_t) (address->port >> 8);
    wire[length - 1] = (uint8_t) address->port;
    *written         = length;
    return true;
}
