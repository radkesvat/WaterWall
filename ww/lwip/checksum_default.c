#include "wlibc.h"


extern uint16_t checksumAVX2(const uint8_t *data, size_t len, uint16_t initial);
extern uint16_t checksumSSE2(const uint8_t *data, size_t len, uint16_t initial);
extern uint16_t checksumAMD64(const uint8_t *data, size_t len, uint16_t initial);
extern uint16_t checksumDefault(const uint8_t *data, size_t len, uint16_t initial);

/** Sum the pseudo‑header (src, dst, proto, length) in host order */
static inline uint32_t checksumPseudoHeader(const struct ip4_addr_packed *src, const struct ip4_addr_packed *dst,
                                              u8_t proto, u16_t length)
{
    uint32_t sum   = 0;
    uint32_t src_h = lwip_ntohl(src->addr);
    uint32_t dst_h = lwip_ntohl(dst->addr);

    /* high and low 16 bits of source address */
    sum += (src_h >> 16) & 0xFFFF;
    sum += src_h & 0xFFFF;
    /* high and low 16 bits of destination address */
    sum += (dst_h >> 16) & 0xFFFF;
    sum += dst_h & 0xFFFF;
    /* protocol (zero‑padded high byte + proto in low byte) */
    sum += proto;
    /* TCP/UDP length */
    sum += length;

    return sum;
}

/** Sum the payload buffer as 16‑bit big‑endian words */
static inline uint32_t checksumBuffer(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;

    // Process 8 bytes (4 words) at a time
    while (len >= 8)
    {
        sum += (data[0] << 8) | data[1];
        sum += (data[2] << 8) | data[3];
        sum += (data[4] << 8) | data[5];
        sum += (data[6] << 8) | data[7];
        data += 8;
        len -= 8;
    }

    // Process remaining complete words (2 bytes)
    while (len >= 2)
    {
        sum += (data[0] << 8) | data[1];
        data += 2;
        len -= 2;
    }

    // Handle odd byte if present
    if (len)
    {
        sum += data[0] << 8;
    }

    return sum;
}

/** Fold carries and return the one's‑complement result */
static inline uint16_t finalizeChecksum(uint32_t sum)
{
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t) ~sum;
}

// /** Compute TCP/UDP checksum including pseudo‑header */
// static uint16_t compute_tcp_udp_checksum(const struct ip4_addr_packed *src, const struct ip4_addr_packed *dst,
//                                          u8_t proto, const uint8_t *transport_hdr, u16_t transport_len)
// {
//     uint32_t sum = checksum_pseudo_header(src, dst, proto, transport_len);
//     sum += checksum_buffer(transport_hdr, transport_len);
//     return finalize_checksum(sum);
// }

static uint16_t cChecksum(const uint8_t *data, size_t len, uint16_t initial)
{
    // simple C fallback: sum data and finalize with initial seed
    uint32_t sum = initial;
    sum += checksumBuffer(data, len);
    return finalizeChecksum(sum);
}

uint16_t checksumAVX2(const uint8_t *data, size_t len, uint16_t initial)
{
    // This is a fallback implementation. if it is supported then the assembly is already used and this file is out.
    return cChecksum(data, len, initial);
}
uint16_t checksumSSE2(const uint8_t *data, size_t len, uint16_t initial)
{
    // This is a fallback implementation. if it is supported then the assembly is already used and this file is out.
    return cChecksum(data, len, initial);
}
uint16_t checksumAMD64(const uint8_t *data, size_t len, uint16_t initial)
{
    // This is a fallback implementation. if it is supported then the assembly is already used and this file is out.
    return cChecksum(data, len, initial);
}
uint16_t checksumDefault(const uint8_t *data, size_t len, uint16_t initial)
{
    // This is a fallback implementation. if it is supported then the assembly is already used and this file is out.
    return cChecksum(data, len, initial);
}
