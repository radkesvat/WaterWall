/*
 * A checksum-valid bit must assert a fact about the bytes.
 *
 * WinDivert reads a set IPChecksum/TCPChecksum/UDPChecksum bit as "this checksum
 * is already correct, do not compute it". The Raw writer set all three from the
 * packet's shape alone - IPv4 means the IP checksum is fine, unfragmented TCP
 * means the TCP checksum is fine - so a node that emitted a packet with a stale
 * or never-computed checksum had that assertion made on its behalf and the
 * driver skipped the correction. A cleared bit costs one computation in the
 * driver and is always accepted, so anything unproven has to stay clear.
 *
 * The writer itself is Windows-only; the decision it now consults is not, so it
 * is tested here against real packets.
 */

#include "devices/device_frag_affinity.h"
#include "wwapi.h"

#include "lwip/inet_chksum.h"
#include "lwip/prot/ip4.h"

enum
{
    kChecksumTestPayload = 24
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static uint16_t onesComplement(const uint8_t *data, uint32_t length)
{
    uint32_t sum = 0;

    for (uint32_t i = 0; i + 1U < length; i += 2U)
    {
        sum += GET_BE16(data + i);
    }
    if ((length % 2U) != 0)
    {
        sum += (uint32_t) data[length - 1U] << 8U;
    }
    while ((sum >> 16U) != 0)
    {
        sum = (sum & UINT32_C(0xFFFF)) + (sum >> 16U);
    }
    return (uint16_t) ~sum;
}

static void writeIpv4Header(uint8_t *packet, uint32_t total_len, uint8_t protocol, uint16_t fragment_bits)
{
    memoryZero(packet, 20);
    packet[0] = 0x45;
    packet[9] = protocol;
    PUT_BE16(packet + 2, (uint16_t) total_len);
    PUT_BE16(packet + 4, 0x4242);
    PUT_BE16(packet + 6, fragment_bits);
    packet[8] = 64;
    PUT_BE32(packet + 12, 0x0A000001U);
    PUT_BE32(packet + 16, 0x0A000002U);
    PUT_BE16(packet + 10, onesComplement(packet, 20));
}

/* Pseudo-header sum over the transport bytes, the same one the stack computes. */
static uint16_t transportChecksum(const uint8_t *packet, uint32_t total_len, uint8_t protocol)
{
    const uint32_t transport_len = total_len - 20U;
    uint32_t       sum           = 0;

    sum += GET_BE16(packet + 12);
    sum += GET_BE16(packet + 14);
    sum += GET_BE16(packet + 16);
    sum += GET_BE16(packet + 18);
    sum += protocol;
    sum += transport_len;

    for (uint32_t i = 0; i + 1U < transport_len; i += 2U)
    {
        sum += GET_BE16(packet + 20 + i);
    }
    if ((transport_len % 2U) != 0)
    {
        sum += (uint32_t) packet[total_len - 1U] << 8U;
    }
    while ((sum >> 16U) != 0)
    {
        sum = (sum & UINT32_C(0xFFFF)) + (sum >> 16U);
    }
    return (uint16_t) ~sum;
}

static uint32_t buildTcp(uint8_t *packet, bool valid)
{
    const uint32_t total_len = 20U + 20U + kChecksumTestPayload;

    writeIpv4Header(packet, total_len, IP_PROTO_TCP, 0);
    memoryZero(packet + 20, total_len - 20U);
    PUT_BE16(packet + 20, 1234);
    PUT_BE16(packet + 22, 443);
    packet[32] = 0x50; /* data offset 5 */
    packet[33] = 0x10; /* ACK */
    PUT_BE16(packet + 34, 8192);
    PUT_BE16(packet + 36, 0);
    PUT_BE16(packet + 36, transportChecksum(packet, total_len, IP_PROTO_TCP));
    if (! valid)
    {
        PUT_BE16(packet + 36, (uint16_t) (GET_BE16(packet + 36) ^ 0x0001U));
    }
    return total_len;
}

static uint32_t buildUdp(uint8_t *packet, bool valid)
{
    const uint32_t total_len = 20U + 8U + kChecksumTestPayload;

    writeIpv4Header(packet, total_len, IP_PROTO_UDP, 0);
    memoryZero(packet + 20, total_len - 20U);
    PUT_BE16(packet + 20, 1234);
    PUT_BE16(packet + 22, 53);
    PUT_BE16(packet + 24, (uint16_t) (total_len - 20U));
    PUT_BE16(packet + 26, 0);
    PUT_BE16(packet + 26, transportChecksum(packet, total_len, IP_PROTO_UDP));
    if (! valid)
    {
        PUT_BE16(packet + 26, (uint16_t) (GET_BE16(packet + 26) ^ 0x0001U));
    }
    return total_len;
}

int main(void)
{
    uint8_t packet[128];

    /* A byte-valid TCP packet: every applicable checksum is provable. */
    uint32_t                          length   = buildTcp(packet, true);
    device_packet_checksum_validity_t validity = deviceIpv4ChecksumValidity(packet, length);
    require(validity.ipv4 && validity.tcp && ! validity.udp, "a byte-valid TCP packet did not prove its checksums");

    /* One flipped transport bit: the IPv4 header is still provable, TCP is not. */
    length   = buildTcp(packet, false);
    validity = deviceIpv4ChecksumValidity(packet, length);
    require(validity.ipv4 && ! validity.tcp && ! validity.udp, "a corrupt TCP checksum was advertised as valid");

    /* A corrupt IPv4 header checksum proves nothing about the header. */
    length = buildTcp(packet, true);
    PUT_BE16(packet + 10, (uint16_t) (GET_BE16(packet + 10) ^ 0x0100U));
    validity = deviceIpv4ChecksumValidity(packet, length);
    require(! validity.ipv4, "a corrupt IPv4 header checksum was advertised as valid");

    length   = buildUdp(packet, true);
    validity = deviceIpv4ChecksumValidity(packet, length);
    require(validity.ipv4 && validity.udp && ! validity.tcp, "a byte-valid UDP packet did not prove its checksums");

    length   = buildUdp(packet, false);
    validity = deviceIpv4ChecksumValidity(packet, length);
    require(validity.ipv4 && ! validity.udp, "a corrupt UDP checksum was advertised as valid");

    /* A UDP checksum of zero is "not computed", which is legal and unprovable. */
    length = buildUdp(packet, true);
    PUT_BE16(packet + 26, 0);
    validity = deviceIpv4ChecksumValidity(packet, length);
    require(validity.ipv4 && validity.udp, "an explicitly omitted UDP checksum was rejected");

    /* One fragment never carries the whole transport checksum's input. */
    length = buildTcp(packet, true);
    PUT_BE16(packet + 6, 0x2000U); /* MF */
    PUT_BE16(packet + 10, 0);
    PUT_BE16(packet + 10, onesComplement(packet, 20));
    validity = deviceIpv4ChecksumValidity(packet, length);
    require(validity.ipv4 && ! validity.tcp && ! validity.udp,
            "a fragment advertised a transport checksum it cannot carry");

    /* A truncated or non-IPv4 packet proves nothing at all. */
    length   = buildTcp(packet, true);
    validity = deviceIpv4ChecksumValidity(packet, 10);
    require(! validity.ipv4 && ! validity.tcp && ! validity.udp, "a truncated packet proved a checksum");

    packet[0] = 0x60;
    validity  = deviceIpv4ChecksumValidity(packet, length);
    require(! validity.ipv4 && ! validity.tcp && ! validity.udp, "a non-IPv4 packet proved an IPv4 checksum");

    validity = deviceIpv4ChecksumValidity(NULL, 0);
    require(! validity.ipv4 && ! validity.tcp && ! validity.udp, "a null packet proved a checksum");

    /* A declared total length that disagrees with the buffer is not a packet. */
    length = buildTcp(packet, true);
    PUT_BE16(packet + 2, (uint16_t) (length + 4U));
    PUT_BE16(packet + 10, 0);
    PUT_BE16(packet + 10, onesComplement(packet, 20));
    validity = deviceIpv4ChecksumValidity(packet, length);
    require(! validity.ipv4 && ! validity.tcp, "a length-mismatched packet proved a checksum");

    puts("device checksum validity tests passed");
    return 0;
}
