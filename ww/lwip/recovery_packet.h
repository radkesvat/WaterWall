#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum
{
    kWwLwipRecoveryPacketMax = 120
};

static inline uint32_t wwLwipRecoveryChecksumSum(const uint8_t *bytes, size_t length, uint32_t sum)
{
    while (length >= 2)
    {
        sum += ((uint32_t) bytes[0] << 8) | bytes[1];
        bytes += 2;
        length -= 2;
    }
    if (length != 0)
        sum += (uint32_t) bytes[0] << 8;
    while (sum >> 16)
        sum = (sum & UINT32_C(65535)) + (sum >> 16);
    return sum;
}

/* Only complete, header-only IPv4 TCP ACK/RST packets qualify. FIN can retain
 * out-of-order state, and SYN can create a connection, so neither is recovery
 * traffic. Byte reads permit unaligned ingress; trusted TUN checksums preserve
 * the existing adapter trust boundary without relaxing structural validation. */
static inline bool wwLwipPacketIsRecovery(const void *packet, size_t length, bool trust_checksums)
{
    const uint8_t *bytes = packet;
    if (length < 40 || length > kWwLwipRecoveryPacketMax || (bytes[0] >> 4) != 4 || bytes[9] != 6)
        return false;
    const size_t ip_length = (size_t) (bytes[0] & 15U) * 4U;
    if (ip_length < 20 || ip_length > length - 20 || (((size_t) bytes[2] << 8) | bytes[3]) != length ||
        ((((unsigned) bytes[6] << 8) | bytes[7]) & 0xbfffU) != 0)
        return false;
    const uint8_t *tcp        = bytes + ip_length;
    const size_t   tcp_length = (size_t) (tcp[12] >> 4) * 4U;
    const unsigned flags      = tcp[13];
    if (tcp_length < 20 || ip_length + tcp_length != length || (tcp[12] & 15U) != 0 || (flags & 0x2bU) != 0 ||
        (flags & 0x14U) == 0)
        return false;
    if (trust_checksums)
        return true;
    if (wwLwipRecoveryChecksumSum(bytes, ip_length, 0) != UINT32_C(65535))
        return false;
    uint32_t sum = wwLwipRecoveryChecksumSum(bytes + 12, 8, (uint32_t) tcp_length + 6U);
    return wwLwipRecoveryChecksumSum(tcp, tcp_length, sum) == UINT32_C(65535);
}
