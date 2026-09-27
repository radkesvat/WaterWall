#include "devices/device_packet_checksum.h"
#include "devices/device_packet_checksum_internal.h"
#include "lwip/inet_chksum.h"
#include "lwip/prot/tcp.h"
#include "lwip/prot/udp.h"
#include "wchecksum.h"

enum
{
    kDeviceFragAffinityIpv4MoreFragments = 0x2000,
    kDeviceFragAffinityIpv4OffsetMask    = 0x1fff
};

static bool deviceIpv4NormalizeHeaderChecksum(uint8_t *packet, uint32_t length)
{
    if (packet == NULL || length < 20 || (packet[0] >> 4U) != 4)
    {
        return false;
    }

    const uint32_t header_len = (uint32_t) (packet[0] & 0x0FU) * 4U;
    if (header_len < 20 || header_len > 60 || header_len > length || GET_BE16(packet + 2) != length)
    {
        return false;
    }

    PUT_BE16(packet + 10, 0);
    PUT_BE16(packet + 10, deviceIpv4HeaderChecksum(packet, header_len));
    return true;
}

static bool deviceIpv4TransportChecksumValid(const uint8_t *packet, uint32_t length, uint32_t header_len,
                                             uint8_t protocol)
{
    const uint16_t transport_len = (uint16_t) (length - header_len);
    const uint8_t *transport     = packet + header_len;
    ip4_addr_t     source;
    ip4_addr_t     destination;

    memoryCopy(&source.addr, packet + 12, sizeof(source.addr));
    memoryCopy(&destination.addr, packet + 16, sizeof(destination.addr));

    if (protocol == IP_PROTO_TCP)
    {
        if (transport_len < TCP_HLEN || ((uint32_t) (transport[12] >> 4U) * 4U) < TCP_HLEN ||
            ((uint32_t) (transport[12] >> 4U) * 4U) > transport_len)
        {
            return false;
        }
    }
    else if (protocol == IP_PROTO_UDP)
    {
        if (transport_len < UDP_HLEN || GET_BE16(transport + 4) != transport_len)
        {
            return false;
        }
        if (GET_BE16(transport + 6) == 0)
        {
            return true;
        }
    }
    else
    {
        return true;
    }

    struct pbuf transport_pbuf = {
        .next    = NULL,
        .payload = (void *) transport,
        .tot_len = transport_len,
        .len     = transport_len,
        .ref     = 1,
    };
    return inet_chksum_pseudo(&transport_pbuf, protocol, transport_len, &source, &destination) == 0;
}

bool deviceIpv4PreparePacketChecksums(uint8_t *packet, uint32_t length, device_packet_checksum_provenance_t provenance)
{
    if (packet == NULL || length == 0)
    {
        return false;
    }
    if ((packet[0] >> 4U) != 4)
    {
        return true;
    }
    if (length < 20)
    {
        return false;
    }

    const uint32_t header_len = (uint32_t) (packet[0] & 0x0FU) * 4U;
    if (header_len < 20 || header_len > 60 || header_len > length || GET_BE16(packet + 2) != length)
    {
        return false;
    }

    const uint8_t  protocol      = packet[9];
    const uint16_t fragment_bits = GET_BE16(packet + 6);
    const bool     fragmented =
        (fragment_bits & (kDeviceFragAffinityIpv4MoreFragments | kDeviceFragAffinityIpv4OffsetMask)) != 0;
    const device_ipv4_checksum_provenance_t transport_provenance =
        protocol == IP_PROTO_TCP ? provenance.tcp
                                 : (protocol == IP_PROTO_UDP ? provenance.udp : kDeviceIpv4ChecksumProvenValid);

    /* Validate every untrusted field before any trusted offload field is repaired. */
    if (provenance.ipv4 == kDeviceIpv4ChecksumUntrusted && ! deviceIpv4HeaderChecksumValid(packet, header_len))
    {
        return false;
    }
    if (! fragmented && transport_provenance == kDeviceIpv4ChecksumUntrusted &&
        ! deviceIpv4TransportChecksumValid(packet, length, header_len, protocol))
    {
        return false;
    }

    if (fragmented)
    {
        if (transport_provenance == kDeviceIpv4ChecksumOffloadNotReady)
        {
            return false;
        }
        return provenance.ipv4 != kDeviceIpv4ChecksumOffloadNotReady ||
               deviceIpv4NormalizeHeaderChecksum(packet, length);
    }

    if (transport_provenance == kDeviceIpv4ChecksumOffloadNotReady)
    {
        return calcFullPacketChecksum(packet, length);
    }
    if (provenance.ipv4 == kDeviceIpv4ChecksumOffloadNotReady)
    {
        return calcIpv4HeaderChecksum(packet, length);
    }
    return true;
}

device_packet_checksum_validity_t deviceIpv4ChecksumValidity(const uint8_t *packet, uint32_t length)
{
    device_packet_checksum_validity_t validity = {0};

    if (packet == NULL || length < 20 || (packet[0] >> 4U) != 4)
    {
        return validity;
    }

    const uint32_t header_len = (uint32_t) (packet[0] & 0x0FU) * 4U;
    if (header_len < 20 || header_len > 60 || header_len > length || GET_BE16(packet + 2) != length)
    {
        return validity;
    }

    validity.ipv4 = deviceIpv4HeaderChecksumValid(packet, header_len);

    /* One fragment never carries the whole transport checksum's input. */
    const uint16_t fragment_bits = GET_BE16(packet + 6);
    if ((fragment_bits & (kDeviceFragAffinityIpv4MoreFragments | kDeviceFragAffinityIpv4OffsetMask)) != 0)
    {
        return validity;
    }

    const uint8_t protocol = packet[9];
    if (protocol != IP_PROTO_TCP && protocol != IP_PROTO_UDP)
    {
        return validity;
    }

    const bool transport_valid = deviceIpv4TransportChecksumValid(packet, length, header_len, protocol);
    validity.tcp               = transport_valid && protocol == IP_PROTO_TCP;
    validity.udp               = transport_valid && protocol == IP_PROTO_UDP;
    return validity;
}
