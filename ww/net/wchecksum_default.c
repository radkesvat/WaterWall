#include "wlibc.h"


extern uint16_t checksumDefault(const uint8_t *data, size_t len, uint32_t initial);

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

/** Helper function to read 64-bit big-endian value from buffer */
static inline uint64_t readBigEndian64(const uint8_t *data)
{
    return ((uint64_t)data[0] << 56) | ((uint64_t)data[1] << 48) | ((uint64_t)data[2] << 40) | ((uint64_t)data[3] << 32) |
           ((uint64_t)data[4] << 24) | ((uint64_t)data[5] << 16) | ((uint64_t)data[6] << 8) | data[7];
}

/** Helper function to read 32-bit big-endian value from buffer */
static inline uint32_t readBigEndian32(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
}

/** Helper function to read 16-bit big-endian value from buffer */
static inline uint16_t readBigEndian16(const uint8_t *data)
{
    return (data[0] << 8) | data[1];
}

/** Helper function to add value to sum with carry tracking */
static inline void addWithCarry(uint64_t *sum, uint64_t *carry, uint64_t val)
{
    uint64_t old_sum = *sum;
    *sum += val;
    if (*sum < old_sum) (*carry)++;
}

/** Sum the payload buffer as 16‑bit big‑endian words */
static inline uint32_t checksumBuffer(const uint8_t *data, size_t len)
{
    uint64_t sum = 0;
    uint64_t carry = 0;

    // Process 64 bytes (32 words) at a time for maximum unrolling
    while (len >= 64)
    {
        addWithCarry(&sum, &carry, readBigEndian64(data));
        addWithCarry(&sum, &carry, readBigEndian64(data + 8));
        addWithCarry(&sum, &carry, readBigEndian64(data + 16));
        addWithCarry(&sum, &carry, readBigEndian64(data + 24));
        addWithCarry(&sum, &carry, readBigEndian64(data + 32));
        addWithCarry(&sum, &carry, readBigEndian64(data + 40));
        addWithCarry(&sum, &carry, readBigEndian64(data + 48));
        addWithCarry(&sum, &carry, readBigEndian64(data + 56));
        data += 64;
        len -= 64;
    }

    // Process 32 bytes at a time
    while (len >= 32)
    {
        addWithCarry(&sum, &carry, readBigEndian64(data));
        addWithCarry(&sum, &carry, readBigEndian64(data + 8));
        addWithCarry(&sum, &carry, readBigEndian64(data + 16));
        addWithCarry(&sum, &carry, readBigEndian64(data + 24));
        data += 32;
        len -= 32;
    }

    // Process 16 bytes at a time
    while (len >= 16)
    {
        addWithCarry(&sum, &carry, readBigEndian64(data));
        addWithCarry(&sum, &carry, readBigEndian64(data + 8));
        data += 16;
        len -= 16;
    }

    // Process 8 bytes at a time
    while (len >= 8)
    {
        addWithCarry(&sum, &carry, readBigEndian64(data));
        data += 8;
        len -= 8;
    }

    // Process 4 bytes at a time
    while (len >= 4)
    {
        addWithCarry(&sum, &carry, readBigEndian32(data));
        data += 4;
        len -= 4;
    }

    // Process remaining complete words (2 bytes)
    while (len >= 2)
    {
        addWithCarry(&sum, &carry, readBigEndian16(data));
        data += 2;
        len -= 2;
    }

    // Handle odd byte if present
    if (len)
    {
        addWithCarry(&sum, &carry, (uint64_t)data[0] << 8);
    }

    // Fold the 64-bit sum with carry into a 32-bit result
    sum += carry;
    while (sum >> 32)
    {
        sum = (sum & 0xFFFFFFFF) + (sum >> 32);
    }

    return (uint32_t)sum;
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

// returns checksum in big endian
static uint16_t cChecksum(const uint8_t *data, size_t len, uint32_t initial)
{
    // simple C fallback: sum data and finalize with initial seed
    uint32_t sum = initial;
    sum += checksumBuffer(data, len);
    return lwip_htons(finalizeChecksum(sum));
}

// returns checksum in big endian
uint16_t checksumDefault(const uint8_t *data, size_t len, uint32_t initial)
{
    return cChecksum(data, len, initial);
}
