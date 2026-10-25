#include "VmessCommon/crypto.h"

/* sing-vmess a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017 packetaddr
 * uses sing ab3827767cea common/metadata/serializer.go's default ordering:
 * family, address, then big-endian port. It has no domain-family mapping. */
bool vmessIsPacketAddrDomain(const uint8_t *domain, size_t length)
{
    assert(domain != NULL || length == 0);
    static const uint8_t marker[] = VMESS_PACKETADDR_DOMAIN;
    return length == sizeof(marker) - 1 && memcmp(domain, marker, sizeof(marker) - 1) == 0;
}

bool vmessRequestIsPacketAddr(const vmess_request_header_t *header)
{
    assert(header != NULL);
    return header->command == 2 && header->port == 0 && header->address_type == 2 &&
           vmessIsPacketAddrDomain(header->address, header->address_length);
}

size_t vmessPacketAddrHeaderSize(const vmess_packet_addr_t *address)
{
    assert(address != NULL);
    return address->address_type == 1 ? 7 : address->address_type == 3 ? 19 : 0;
}

wcrypto_status_t vmessPacketAddrEncode(const vmess_packet_addr_t *address, uint8_t *out, size_t capacity,
                                       size_t *header_length)
{
    assert(address != NULL && header_length != NULL && (out != NULL || capacity == 0));
    *header_length = 0;
    size_t needed  = vmessPacketAddrHeaderSize(address);
    if (needed == 0 || address->port == 0)
    {
        return kWCryptoInvalidArgument;
    }
    if (capacity < needed)
    {
        return kWCryptoInputTooLarge;
    }
    out[0] = address->address_type == 1 ? 1 : 2;
    memcpy(out + 1, address->address, needed - 3);
    out[needed - 2] = (uint8_t) (address->port >> 8);
    out[needed - 1] = (uint8_t) address->port;
    *header_length  = needed;
    return kWCryptoOk;
}

wcrypto_status_t vmessPacketAddrDecode(const uint8_t *record, size_t length, vmess_packet_addr_t *out,
                                       size_t *header_length)
{
    assert((record != NULL || length == 0) && out != NULL && header_length != NULL);
    memset(out, 0, sizeof(*out));
    *header_length = 0;
    size_t needed  = length != 0 ? (record[0] == 1 ? 7 : record[0] == 2 ? 19 : 0) : 0;
    if (needed == 0 || length < needed)
    {
        return kWCryptoInvalidArgument;
    }
    uint16_t port = (uint16_t) (((uint16_t) record[needed - 2] << 8) | record[needed - 1]);
    if (port == 0)
    {
        return kWCryptoInvalidArgument;
    }
    out->address_type = record[0] == 1 ? 1 : 3;
    memcpy(out->address, record + 1, needed - 3);
    out->port      = port;
    *header_length = needed;
    return kWCryptoOk;
}
