#include "devices/tun/tun_linux_gso_write.h"

#include "wchecksum.h"
#include <limits.h>
#include <linux/virtio_net.h>

_Static_assert(kTunWriteBatchPackets + 2 <= UIO_MAXIOV, "writer record exceeds Linux iovec limit");

typedef struct tcp_packet_s
{
    const uint8_t *ip;
    uint32_t       sequence;
    uint16_t       id;
    uint16_t       header_length;
    uint16_t       payload_length;
    bool           psh;
} tcp_packet_t;

static bool classify(const sbuf_t *buffer, uint16_t mtu, tcp_packet_t *packet)
{
    const uint32_t length = sbufGetLength(buffer);
    if (length <= 40 || length > mtu || sbufIsSplice(buffer))
        return false;
    const uint8_t *ip = sbufGetRawPtr(buffer);
    if (ip[0] != 0x45 || GET_BE16(ip + 2) != length || ip[9] != 6 || (GET_BE16(ip + 6) & ~0x4000U) != 0 ||
        calcGenericChecksum(ip, 20, 0) != 0)
        return false;
    const uint16_t header_length = 20U + (uint16_t) (ip[32] >> 4U) * 4U;
    /* NS/reserved and every flag except ACK/PSH are unsupported. */
    if ((ip[32] & 0x0fU) != 0 || (ip[33] & ~0x08U) != 0x10 || header_length < 40 || header_length >= length)
        return false;
    *packet = (tcp_packet_t) {.ip             = ip,
                              .sequence       = GET_BE32(ip + 24),
                              .id             = GET_BE16(ip + 4),
                              .header_length  = header_length,
                              .payload_length = length - header_length,
                              .psh            = (ip[33] & 0x08U) != 0};
    return true;
}

static bool compatible(const tcp_packet_t *first, const tcp_packet_t *next, uint32_t sequence, uint16_t id)
{
    const uint8_t *a = first->ip;
    const uint8_t *b = next->ip;
    return next->sequence == sequence && next->id == id && next->header_length == first->header_length &&
           next->payload_length <= first->payload_length && a[1] == b[1] &&
           memoryEqual(a + 6, b + 6, 4) &&                          /* TOS, DF, TTL, protocol */
           memoryEqual(a + 12, b + 12, 12) &&                       /* addresses and ports */
           memoryEqual(a + 28, b + 28, 5) &&                        /* ACK, data offset and reserved */
           memoryEqual(a + 34, b + 34, 2) &&                        /* window */
           memoryEqual(a + 38, b + 38, first->header_length - 38U); /* urgent pointer/options */
}

static void little16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t) value;
    bytes[1] = (uint8_t) (value >> 8U);
}

unsigned tunLinuxGsoBuildWrite(sbuf_t *const *packets, unsigned count, uint16_t mtu, tun_linux_gso_write_t *record)
{
    assert(packets != NULL && record != NULL && count > 0 && count <= kTunWriteBatchPackets);
    tcp_packet_t first;
    if (! classify(packets[0], mtu, &first) || first.psh || count < 2)
        return 1;

    uint32_t length   = first.header_length + first.payload_length;
    uint32_t sequence = first.sequence + first.payload_length;
    unsigned used     = 1;
    bool     psh      = false;
    record->iov[2] =
        (struct iovec) {.iov_base = (void *) (first.ip + first.header_length), .iov_len = first.payload_length};
    while (used < count)
    {
        tcp_packet_t next;
        if (! classify(packets[used], mtu, &next) ||
            ! compatible(&first, &next, sequence, (uint16_t) (first.id + used)) ||
            length + next.payload_length > UINT16_MAX)
            break;
        record->iov[used + 2] =
            (struct iovec) {.iov_base = (void *) (next.ip + next.header_length), .iov_len = next.payload_length};
        length += next.payload_length;
        sequence += next.payload_length;
        ++used;
        psh = next.psh;
        if (psh || next.payload_length < first.payload_length)
            break;
    }
    if (used < 2)
        return 1;

    /* Only the bounded header is copied. Do not present it to a full-packet
     * parser as though the aggregate's payload were contiguous behind it. */
    memoryCopy(record->header, first.ip, first.header_length);
    uint8_t *ip = record->header;
    ip[2]       = (uint8_t) (length >> 8U);
    ip[3]       = (uint8_t) length;
    ip[10] = ip[11]         = 0;
    const uint16_t checksum = calcGenericChecksum(ip, 20, 0);
    memoryCopy(ip + 10, &checksum, sizeof(checksum));
    ip[33] = 0x10U | (psh ? 0x08U : 0U);
    uint32_t seed =
        (uint32_t) GET_BE16(ip + 12) + GET_BE16(ip + 14) + GET_BE16(ip + 16) + GET_BE16(ip + 18) + 6U + length - 20U;
    while (seed > UINT16_MAX)
        seed = (seed & UINT16_MAX) + (seed >> 16U);
    ip[36] = (uint8_t) (seed >> 8U);
    ip[37] = (uint8_t) seed;
    memoryZero(record->metadata, sizeof(record->metadata));
    record->metadata[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    record->metadata[1] = VIRTIO_NET_HDR_GSO_TCPV4;
    little16(record->metadata + 2, first.header_length);
    little16(record->metadata + 4, first.payload_length);
    little16(record->metadata + 6, 20);
    little16(record->metadata + 8, 16);
    record->iov[0] = (struct iovec) {.iov_base = record->metadata, .iov_len = sizeof(record->metadata)};
    record->iov[1] = (struct iovec) {.iov_base = record->header, .iov_len = first.header_length};
    record->length = length + sizeof(record->metadata);
    record->count  = used + 2;
    return used;
}
