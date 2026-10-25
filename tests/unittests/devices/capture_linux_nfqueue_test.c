/*
 * Covers: Verifies the Linux NFQUEUE netlink parser with synthetic messages, including capture-length
 * byte order, malformed attributes, payload cursor exposure, truncated-prefix packet-id recovery,
 * and nonblocking receive/verdict ownership across syscall refusal and interruption.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: testValidPayload, testExposePayloadView, testCaptureLengthDiscard,
 * testPayloadAbovePolicyDiscarded, testDuplicateAttributesRejected, testShortAttributesRejected,
 * testMalformedBoundsRejected, testCaptureLengthLessThanPayloadRejected; the driver lists the remaining
 * cases
 * Checks: Assertion labels include: builder overflow; valid payload was not accepted; valid payload did not
 * expose packet id; packet id byte order changed
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.capture_linux_nfqueue_unit
 */
#include "wwapi.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#include "devices/capture/capture_linux_checksum.h"
#include "devices/capture/capture_linux_internal.h"
#include "devices/capture/capture_linux_nfqueue.h"
#include "devices/device_packet_checksum.h"

#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <poll.h>
#include <sys/socket.h>

enum
{
    kTestPacketId = 0x10203040U,
    kTestSocket   = 71,
    kTestQueue    = 377
};

typedef struct nfqueue_io_fixture_s
{
    _Alignas(ww_max_align_t) uint8_t message[kCaptureLinuxNetfilterReadBufferSize];
    size_t                       message_length;
    size_t                       datagram_length;
    unsigned int                 receive_calls;
    unsigned int                 verdict_calls;
    unsigned int                 poll_calls;
    unsigned int                 receive_failures;
    unsigned int                 verdict_failures;
    int                          receive_errno;
    int                          verdict_errno;
    bool                         short_verdict;
    struct nfqnl_msg_verdict_hdr last_verdict;
    uint16_t                     last_queue;
} nfqueue_io_fixture_t;

static nfqueue_io_fixture_t io_fixture;

ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags);
ssize_t __wrap_sendto(int fd, const void *data, size_t length, int flags, const struct sockaddr *destination,
                      socklen_t address_length);
int     __wrap_poll(struct pollfd *fds, nfds_t count, int timeout);

ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags)
{
    require(fd == kTestSocket, "receive used the wrong NFQUEUE socket");
    require((flags & (MSG_DONTWAIT | MSG_TRUNC)) == (MSG_DONTWAIT | MSG_TRUNC),
            "receive did not request nonblocking truncation detection");
    ++io_fixture.receive_calls;
    if (io_fixture.receive_failures != 0)
    {
        --io_fixture.receive_failures;
        errno = io_fixture.receive_errno;
        return -1;
    }
    require(message->msg_iovlen == 1, "receive changed packet storage shape");
    require(message->msg_namelen == sizeof(struct sockaddr_nl), "receive did not provide Netlink address storage");
    struct sockaddr_nl *address = message->msg_name;
    *address                    = (struct sockaddr_nl) {.nl_family = AF_NETLINK};
    const size_t copied         = min(io_fixture.message_length, message->msg_iov[0].iov_len);
    memoryCopy(message->msg_iov[0].iov_base, io_fixture.message, copied);
    message->msg_flags = io_fixture.datagram_length > message->msg_iov[0].iov_len ? MSG_TRUNC : 0;
    return (ssize_t) io_fixture.datagram_length;
}

ssize_t __wrap_sendto(int fd, const void *data, size_t length, int flags, const struct sockaddr *destination,
                      socklen_t address_length)
{
    require(fd == kTestSocket, "verdict used the wrong NFQUEUE socket");
    require((flags & MSG_DONTWAIT) != 0, "verdict send can block");
    require(address_length == sizeof(struct sockaddr_nl), "verdict Netlink address has wrong length");
    const struct sockaddr_nl *address = (const struct sockaddr_nl *) destination;
    require(address->nl_family == AF_NETLINK && address->nl_pid == 0 && address->nl_groups == 0,
            "verdict did not target the kernel");

    const struct nlmsghdr *header = data;
    require(header->nlmsg_len == length, "verdict message length mismatch");
    require(header->nlmsg_type == ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT), "wrong verdict message type");
    require(header->nlmsg_flags == NLM_F_REQUEST, "verdict unexpectedly requests an ACK");
    const struct nfgenmsg *generic = NLMSG_DATA(header);
    io_fixture.last_queue          = ntohs(generic->res_id);
    const struct nfattr *attribute = NFM_NFA(generic);
    require(attribute->nfa_type == NFQA_VERDICT_HDR && NFA_PAYLOAD(attribute) == sizeof(io_fixture.last_verdict),
            "verdict attribute geometry mismatch");
    memoryCopy(&io_fixture.last_verdict, NFA_DATA(attribute), sizeof(io_fixture.last_verdict));
    ++io_fixture.verdict_calls;
    if (io_fixture.verdict_failures != 0)
    {
        --io_fixture.verdict_failures;
        errno = io_fixture.verdict_errno;
        return -1;
    }
    return (ssize_t) length - (io_fixture.short_verdict ? 1 : 0);
}

int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    discard fds;
    discard count;
    discard timeout;
    ++io_fixture.poll_calls;
    errno = EIO;
    return -1;
}

typedef struct nfqueue_message_builder_s
{
    uint8_t         *data;
    size_t           capacity;
    struct nlmsghdr *nlh;
} nfqueue_message_builder_t;

static size_t nfqueueAttrOffset(void)
{
    return (size_t) NLMSG_HDRLEN + (size_t) NLMSG_ALIGN(sizeof(struct nfgenmsg));
}

static void nfqueueBuilderInit(nfqueue_message_builder_t *builder, uint8_t *data, size_t capacity)
{
    memoryZero(data, capacity);
    builder->data     = data;
    builder->capacity = capacity;
    builder->nlh      = (struct nlmsghdr *) data;

    builder->nlh->nlmsg_len   = (uint32_t) NLMSG_LENGTH(sizeof(struct nfgenmsg));
    builder->nlh->nlmsg_type  = (uint16_t) ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET);
    builder->nlh->nlmsg_flags = 0;
    builder->nlh->nlmsg_seq   = 0;
    builder->nlh->nlmsg_pid   = 0;

    struct nfgenmsg *gen = (struct nfgenmsg *) NLMSG_DATA(builder->nlh);
    gen->nfgen_family    = AF_UNSPEC;
    gen->version         = NFNETLINK_V0;
    gen->res_id          = 0;
}

static struct nfattr *nfqueueBuilderAppendAttr(nfqueue_message_builder_t *builder, uint16_t type, const void *payload,
                                               uint16_t payload_len)
{
    size_t offset     = (size_t) NLMSG_ALIGN(builder->nlh->nlmsg_len);
    size_t attr_len   = (size_t) NFA_LENGTH(payload_len);
    size_t attr_space = (size_t) NFA_ALIGN(attr_len);

    require(offset <= builder->capacity && attr_space <= builder->capacity - offset, "builder overflow");

    struct nfattr *attr = (struct nfattr *) (void *) (builder->data + offset);
    memoryZero(attr, attr_space);
    attr->nfa_type = type;
    attr->nfa_len  = (uint16_t) attr_len;
    if (payload_len > 0 && payload != NULL)
    {
        memoryCopy(NFA_DATA(attr), payload, payload_len);
    }

    builder->nlh->nlmsg_len = (uint32_t) (offset + attr_space);
    return attr;
}

static void fillPayload(uint8_t *payload, uint32_t len)
{
    for (uint32_t i = 0; i < len; ++i)
    {
        payload[i] = (uint8_t) ((i * 17U) + 3U);
    }
}

static struct nfattr *nfqueueBuilderAppendPacketHeader(nfqueue_message_builder_t *builder)
{
    struct nfqnl_msg_packet_hdr packet_hdr;
    memoryZero(&packet_hdr, sizeof(packet_hdr));
    packet_hdr.packet_id   = htonl(kTestPacketId);
    packet_hdr.hw_protocol = htons(0x0800U);
    packet_hdr.hook        = 0;

    return nfqueueBuilderAppendAttr(builder, NFQA_PACKET_HDR, &packet_hdr, (uint16_t) sizeof(packet_hdr));
}

static struct nfattr *nfqueueBuilderAppendPayload(nfqueue_message_builder_t *builder, const uint8_t *payload,
                                                  uint16_t payload_len)
{
    return nfqueueBuilderAppendAttr(builder, NFQA_PAYLOAD, payload, payload_len);
}

static struct nfattr *nfqueueBuilderAppendCaptureLength(nfqueue_message_builder_t *builder, uint32_t cap_len)
{
    uint32_t wire_cap_len = htonl(cap_len);
    return nfqueueBuilderAppendAttr(builder, NFQA_CAP_LEN, &wire_cap_len, (uint16_t) sizeof(wire_cap_len));
}

static size_t nfqueueBuilderLen(const nfqueue_message_builder_t *builder)
{
    return (size_t) builder->nlh->nlmsg_len;
}

static netfilter_packet_parse_result_t parseBuilt(nfqueue_message_builder_t *builder, netfilter_packet_view_t *view)
{
    return captureLinuxNetfilterParsePacket(builder->data, nfqueueBuilderLen(builder), view);
}

static void testValidPayload(uint32_t payload_len)
{
    uint8_t                   message[kCaptureLinuxNetfilterReadBufferSize];
    uint8_t                   payload[kMaxAllowedPacketLength];
    nfqueue_message_builder_t builder;
    netfilter_packet_view_t   view;

    fillPayload(payload, payload_len);
    nfqueueBuilderInit(&builder, message, sizeof(message));
    nfqueueBuilderAppendPacketHeader(&builder);
    nfqueueBuilderAppendPayload(&builder, payload, (uint16_t) payload_len);

    require(parseBuilt(&builder, &view) == kNetfilterPacketParseReady, "valid payload was not accepted");
    require(view.has_packet_id, "valid payload did not expose packet id");
    require(view.packet_id == htonl(kTestPacketId), "packet id byte order changed");
    require(! view.has_capture_length, "ordinary packet unexpectedly had capture length");
    require(view.payload_length == payload_len, "valid payload length mismatch");
    require(memoryCompare(view.payload, payload, payload_len) == 0, "valid payload bytes changed");
}

static void testExposePayloadView(void)
{
    uint8_t                   payload[64];
    nfqueue_message_builder_t builder;
    netfilter_packet_view_t   view;
    sbuf_t                   *buf = sbufCreate(kCaptureLinuxNetfilterReadBufferSize);

    fillPayload(payload, sizeof(payload));
    nfqueueBuilderInit(&builder, sbufGetMutablePtr(buf), sbufGetMaximumWriteableSize(buf));
    nfqueueBuilderAppendPacketHeader(&builder);
    nfqueueBuilderAppendPayload(&builder, payload, (uint16_t) sizeof(payload));

    require(parseBuilt(&builder, &view) == kNetfilterPacketParseReady, "sbuf view packet was not accepted");
    captureLinuxNetfilterExposePacket(buf, builder.data, &view);
    require(sbufGetRawPtr(buf) == view.payload, "sbuf cursor does not point at payload");
    require(sbufGetLength(buf) == sizeof(payload), "sbuf payload length mismatch");
    require(memoryCompare(sbufGetRawPtr(buf), payload, sizeof(payload)) == 0, "sbuf payload bytes changed");

    sbufDestroy(buf);
}

static void testCaptureLengthDiscard(uint32_t cap_len)
{
    uint8_t                   message[kCaptureLinuxNetfilterReadBufferSize];
    uint8_t                   payload[kMaxAllowedPacketLength];
    nfqueue_message_builder_t builder;
    netfilter_packet_view_t   view;

    fillPayload(payload, sizeof(payload));
    nfqueueBuilderInit(&builder, message, sizeof(message));
    nfqueueBuilderAppendPacketHeader(&builder);
    nfqueueBuilderAppendPayload(&builder, payload, (uint16_t) sizeof(payload));
    nfqueueBuilderAppendCaptureLength(&builder, cap_len);

    require(parseBuilt(&builder, &view) == kNetfilterPacketParseDiscarded, "capture length was not discarded");
    require(view.has_capture_length, "discarded capture length was not decoded");
    require(view.capture_length == cap_len, "capture length was not decoded with ntohl");
}

static void testPayloadAbovePolicyDiscarded(void)
{
    uint8_t                   message[kCaptureLinuxNetfilterReadBufferSize];
    uint8_t                   payload[kMaxAllowedPacketLength + 1U];
    nfqueue_message_builder_t builder;
    netfilter_packet_view_t   view;

    fillPayload(payload, sizeof(payload));
    nfqueueBuilderInit(&builder, message, sizeof(message));
    nfqueueBuilderAppendPacketHeader(&builder);
    nfqueueBuilderAppendPayload(&builder, payload, (uint16_t) sizeof(payload));

    require(parseBuilt(&builder, &view) == kNetfilterPacketParseDiscarded,
            "payload above packet policy was not discarded");
}

static void testDuplicateAttributesRejected(void)
{
    uint8_t                   message[kCaptureLinuxNetfilterReadBufferSize];
    uint8_t                   payload[16];
    nfqueue_message_builder_t builder;
    netfilter_packet_view_t   view;

    fillPayload(payload, sizeof(payload));

    nfqueueBuilderInit(&builder, message, sizeof(message));
    nfqueueBuilderAppendPacketHeader(&builder);
    nfqueueBuilderAppendPacketHeader(&builder);
    nfqueueBuilderAppendPayload(&builder, payload, (uint16_t) sizeof(payload));
    require(parseBuilt(&builder, &view) == kNetfilterPacketParseMalformed, "duplicate packet header accepted");
    require(view.has_packet_id, "duplicate packet header lost the first packet id");

    nfqueueBuilderInit(&builder, message, sizeof(message));
    nfqueueBuilderAppendPacketHeader(&builder);
    nfqueueBuilderAppendPayload(&builder, payload, (uint16_t) sizeof(payload));
    nfqueueBuilderAppendPayload(&builder, payload, (uint16_t) sizeof(payload));
    require(parseBuilt(&builder, &view) == kNetfilterPacketParseMalformed, "duplicate payload accepted");
    require(view.has_packet_id, "duplicate payload lost packet id");

    nfqueueBuilderInit(&builder, message, sizeof(message));
    nfqueueBuilderAppendPacketHeader(&builder);
    nfqueueBuilderAppendPayload(&builder, payload, (uint16_t) sizeof(payload));
    nfqueueBuilderAppendCaptureLength(&builder, sizeof(payload));
    nfqueueBuilderAppendCaptureLength(&builder, sizeof(payload));
    require(parseBuilt(&builder, &view) == kNetfilterPacketParseMalformed, "duplicate capture length accepted");
    require(view.has_packet_id, "duplicate capture length lost packet id");
}

static void testShortAttributesRejected(void)
{
    uint8_t                     message[kCaptureLinuxNetfilterReadBufferSize];
    uint8_t                     payload[16];
    nfqueue_message_builder_t   builder;
    netfilter_packet_view_t     view;
    struct nfqnl_msg_packet_hdr packet_hdr;
    uint32_t                    cap_len = htonl((uint32_t) sizeof(payload));

    fillPayload(payload, sizeof(payload));
    memoryZero(&packet_hdr, sizeof(packet_hdr));
    packet_hdr.packet_id = htonl(kTestPacketId);

    nfqueueBuilderInit(&builder, message, sizeof(message));
    nfqueueBuilderAppendAttr(&builder, NFQA_PACKET_HDR, &packet_hdr, (uint16_t) (sizeof(packet_hdr) - 1U));
    nfqueueBuilderAppendPayload(&builder, payload, (uint16_t) sizeof(payload));
    require(parseBuilt(&builder, &view) == kNetfilterPacketParseMalformed, "short packet header accepted");
    require(! view.has_packet_id, "short packet header produced a packet id");

    nfqueueBuilderInit(&builder, message, sizeof(message));
    nfqueueBuilderAppendPacketHeader(&builder);
    nfqueueBuilderAppendPayload(&builder, payload, (uint16_t) sizeof(payload));
    nfqueueBuilderAppendAttr(&builder, NFQA_CAP_LEN, &cap_len, (uint16_t) (sizeof(cap_len) - 1U));
    require(parseBuilt(&builder, &view) == kNetfilterPacketParseMalformed, "short capture length accepted");
    require(view.has_packet_id, "short capture length lost packet id");
}

static void testMalformedBoundsRejected(void)
{
    uint8_t                   message[kCaptureLinuxNetfilterReadBufferSize];
    uint8_t                   payload[16];
    nfqueue_message_builder_t builder;
    netfilter_packet_view_t   view;
    struct nfattr            *payload_attr;
    size_t                    original_len;

    fillPayload(payload, sizeof(payload));

    nfqueueBuilderInit(&builder, message, sizeof(message));
    nfqueueBuilderAppendPacketHeader(&builder);
    payload_attr          = nfqueueBuilderAppendPayload(&builder, payload, (uint16_t) sizeof(payload));
    payload_attr->nfa_len = (uint16_t) NFA_LENGTH(200);
    require(parseBuilt(&builder, &view) == kNetfilterPacketParseMalformed,
            "attribute extending beyond message accepted");
    require(view.has_packet_id, "oversized attribute lost packet id");

    nfqueueBuilderInit(&builder, message, sizeof(message));
    nfqueueBuilderAppendPacketHeader(&builder);
    payload_attr           = nfqueueBuilderAppendPayload(&builder, payload, (uint16_t) sizeof(payload));
    original_len           = nfqueueBuilderLen(&builder);
    builder.nlh->nlmsg_len = (uint32_t) (original_len - 4U);
    discard payload_attr;
    require(parseBuilt(&builder, &view) == kNetfilterPacketParseMalformed,
            "payload extending beyond nlmsg_len accepted");
    require(view.has_packet_id, "short nlmsg_len lost packet id");

    nfqueueBuilderInit(&builder, message, sizeof(message));
    nfqueueBuilderAppendPacketHeader(&builder);
    nfqueueBuilderAppendPayload(&builder, payload, (uint16_t) sizeof(payload));
    builder.nlh->nlmsg_len += 2U;
    require(parseBuilt(&builder, &view) == kNetfilterPacketParseMalformed, "trailing malformed bytes accepted");
    require(view.has_packet_id, "trailing malformed bytes lost packet id");
}

static void testCaptureLengthLessThanPayloadRejected(void)
{
    uint8_t                   message[kCaptureLinuxNetfilterReadBufferSize];
    uint8_t                   payload[32];
    nfqueue_message_builder_t builder;
    netfilter_packet_view_t   view;

    fillPayload(payload, sizeof(payload));
    nfqueueBuilderInit(&builder, message, sizeof(message));
    nfqueueBuilderAppendPacketHeader(&builder);
    nfqueueBuilderAppendPayload(&builder, payload, (uint16_t) sizeof(payload));
    nfqueueBuilderAppendCaptureLength(&builder, 31U);

    require(parseBuilt(&builder, &view) == kNetfilterPacketParseMalformed,
            "capture length smaller than payload accepted");
    require(view.has_packet_id, "cap_len < payload_len lost packet id");
}

static void testPrefixPacketIdRecovery(void)
{
    uint8_t                   message[kCaptureLinuxNetfilterReadBufferSize];
    uint8_t                   payload[512];
    nfqueue_message_builder_t builder;
    uint32_t                  packet_id = 0;

    fillPayload(payload, sizeof(payload));
    nfqueueBuilderInit(&builder, message, sizeof(message));
    nfqueueBuilderAppendPacketHeader(&builder);
    nfqueueBuilderAppendPayload(&builder, payload, (uint16_t) sizeof(payload));
    builder.nlh->nlmsg_len = kCaptureLinuxNetfilterReadBufferSize + 128U;

    size_t complete_packet_header_prefix =
        nfqueueAttrOffset() + (size_t) NFA_ALIGN(NFA_LENGTH(sizeof(struct nfqnl_msg_packet_hdr)));
    require(captureLinuxNetfilterTryReadPacketIdFromPrefix(message, complete_packet_header_prefix, &packet_id),
            "complete prefix did not recover packet id");
    require(packet_id == htonl(kTestPacketId), "prefix packet id byte order changed");

    packet_id = 0;
    require(! captureLinuxNetfilterTryReadPacketIdFromPrefix(
                message, nfqueueAttrOffset() + sizeof(struct nfattr) + 1U, &packet_id),
            "incomplete packet header prefix produced a packet id");
}

static void makeIpv4Packet(uint8_t *packet, uint32_t length, uint8_t protocol)
{
    fillPayload(packet, length);
    memoryZero(packet, 20);
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = protocol;
    PUT_BE16(packet + 2, (uint16_t) length);
    PUT_BE32(packet + 12, UINT32_C(0xC0000201));
    PUT_BE32(packet + 16, UINT32_C(0xC0000202));
}

static void requirePacketPreserved(uint8_t *packet, uint32_t length, bool has_skb_info, uint32_t skb_info)
{
    uint8_t original[128];
    require(length <= sizeof(original), "packet fixture exceeds snapshot storage");
    memoryCopy(original, packet, length);
    require(captureLinuxPreparePacket(packet, length, has_skb_info, skb_info),
            "capture rejected opaque transport bytes or an invalid checksum");
    require(memoryCompare(packet, original, length) == 0, "capture changed opaque packet bytes");
}

static void testOpaqueCapturePayload(void)
{
    uint8_t packet[64];
    makeIpv4Packet(packet, sizeof(packet), IP_PROTO_TCP);
    packet[32] = 0x50;
    packet[33] = 0xFF; // Deliberately unusual TCP flags; checksums are invalid.
    requirePacketPreserved(packet, sizeof(packet), false, 0);
    requirePacketPreserved(packet, sizeof(packet), true, 0);
    requirePacketPreserved(packet, sizeof(packet), false, NFQA_SKB_CSUMNOTREADY);

    for (uint32_t i = 20; i < sizeof(packet); ++i)
    {
        packet[i] ^= 0xA5; // Includes the TCP data offset and checksum.
    }
    requirePacketPreserved(packet, sizeof(packet), true, 0);
    requirePacketPreserved(packet, sizeof(packet), true, NFQA_SKB_CSUMNOTREADY);

    makeIpv4Packet(packet, 21, IP_PROTO_TCP); // Too short to contain a TCP header.
    requirePacketPreserved(packet, 21, true, 0);
    requirePacketPreserved(packet, 21, true, NFQA_SKB_CSUMNOTREADY);

    makeIpv4Packet(packet, sizeof(packet), IP_PROTO_UDP);
    PUT_BE16(packet + 24, 1); // Deliberately invalid UDP length.
    requirePacketPreserved(packet, sizeof(packet), false, 0);
    requirePacketPreserved(packet, sizeof(packet), true, NFQA_SKB_CSUMNOTREADY);

    makeIpv4Packet(packet, sizeof(packet), IP_PROTO_TCP);
    packet[0] = 0x4F; // Bounded IPv4 options, followed by just four transport bytes.
    requirePacketPreserved(packet, sizeof(packet), false, 0);

    makeIpv4Packet(packet, sizeof(packet), IP_PROTO_TCP);
    PUT_BE16(packet + 6, 0x2000); // Fragment validation belongs to the affinity layer.
    requirePacketPreserved(packet, sizeof(packet), true, NFQA_SKB_CSUMNOTREADY);
}

static void testCaptureOffloadCompletion(void)
{
    uint8_t       packet[64];
    const uint8_t protocols[] = {IP_PROTO_TCP, IP_PROTO_UDP};
    for (size_t i = 0; i < sizeof(protocols) / sizeof(protocols[0]); ++i)
    {
        makeIpv4Packet(packet, sizeof(packet), protocols[i]);
        if (protocols[i] == IP_PROTO_TCP)
        {
            packet[32] = 0x50;
        }
        else
        {
            PUT_BE16(packet + 24, sizeof(packet) - 20);
        }
        require(captureLinuxPreparePacket(packet, sizeof(packet), true, NFQA_SKB_CSUMNOTREADY),
                "capture rejected a packet with pending kernel checksum offload");
        const device_packet_checksum_validity_t validity = deviceIpv4ChecksumValidity(packet, sizeof(packet));
        require(validity.ipv4 && (protocols[i] == IP_PROTO_TCP ? validity.tcp : validity.udp),
                "capture failed to finish explicitly pending IPv4/transport checksum offload");
    }
}

static void testCaptureIpv4Bounds(void)
{
    uint8_t packet[40];
    makeIpv4Packet(packet, sizeof(packet), IP_PROTO_TCP);
    require(! captureLinuxPreparePacket(packet, 19, false, 0), "capture accepted a short IPv4 header");
    packet[0] = 0x65;
    require(! captureLinuxPreparePacket(packet, sizeof(packet), false, 0), "capture accepted IPv6");
    packet[0] = 0x44;
    require(! captureLinuxPreparePacket(packet, sizeof(packet), false, 0), "capture accepted an undersized IHL");
    packet[0] = 0x4F;
    require(! captureLinuxPreparePacket(packet, sizeof(packet), false, 0), "capture accepted IHL beyond storage");
    packet[0]                        = 0x45;
    const uint16_t invalid_lengths[] = {19, sizeof(packet) - 1, sizeof(packet) + 1};
    for (size_t i = 0; i < sizeof(invalid_lengths) / sizeof(invalid_lengths[0]); ++i)
    {
        PUT_BE16(packet + 2, invalid_lengths[i]);
        require(! captureLinuxPreparePacket(packet, sizeof(packet), false, 0),
                "capture accepted an inconsistent IPv4 total length");
    }
}

static void prepareReceivedPacket(void)
{
    memoryZero(&io_fixture, sizeof(io_fixture));
    uint8_t packet[64];
    makeIpv4Packet(packet, sizeof(packet), IP_PROTO_TCP);
    nfqueue_message_builder_t builder;
    nfqueueBuilderInit(&builder, io_fixture.message, sizeof(io_fixture.message));
    nfqueueBuilderAppendPacketHeader(&builder);
    nfqueueBuilderAppendPayload(&builder, packet, sizeof(packet));
    io_fixture.message_length  = nfqueueBuilderLen(&builder);
    io_fixture.datagram_length = io_fixture.message_length;
}

static void testReceiveLeavesVerdictWithCaller(void)
{
    prepareReceivedPacket();
    sbuf_t  *buffer    = sbufCreate(kCaptureLinuxNetfilterReadBufferSize);
    uint32_t packet_id = 0;
    require(netfilterReceivePacket(kTestSocket, buffer, &packet_id) == kNetfilterPacketReady,
            "nonblocking receive did not expose a ready IPv4 packet");
    require(packet_id == htonl(kTestPacketId), "receive did not retain the network-order packet id");
    require(sbufGetLength(buffer) == 64 && ((const uint8_t *) sbufGetRawPtr(buffer))[0] == 0x45,
            "receive did not expose just the IP payload");
    require(io_fixture.verdict_calls == 0 && io_fixture.poll_calls == 0, "receive sent a verdict or waited for I/O");

    uint8_t packet[64];
    memoryCopy(packet, sbufGetRawPtr(buffer), sizeof(packet));
    io_fixture.verdict_failures = 1;
    io_fixture.verdict_errno    = EAGAIN;
    require(netfilterTrySendVerdict(kTestSocket, kTestQueue, packet_id, NF_DROP) == kNetfilterVerdictWouldBlock,
            "full verdict socket did not return without waiting");
    require(io_fixture.receive_calls == 1 && memoryCompare(packet, sbufGetRawPtr(buffer), sizeof(packet)) == 0,
            "refused verdict consumed another packet or changed retained input");

    /* Stop may change an unsent active DROP to inactive ACCEPT. No verdict was
     * committed on EAGAIN, so the retained id is still the exact obligation. */
    require(netfilterTrySendVerdict(kTestSocket, kTestQueue, packet_id, NF_ACCEPT) == kNetfilterVerdictSent,
            "retained verdict could not complete after writable readiness");
    require(io_fixture.last_queue == kTestQueue && io_fixture.last_verdict.id == packet_id &&
                ntohl(io_fixture.last_verdict.verdict) == NF_ACCEPT,
            "resumed verdict lost its queue, packet id or stop disposition");
    require(io_fixture.poll_calls == 0, "nonblocking verdict sender entered poll");
    sbufDestroy(buffer);
}

static void testReceiveDiscardRetainsVerdictId(void)
{
    prepareReceivedPacket();
    sbuf_t  *buffer            = sbufCreate(kCaptureLinuxNetfilterReadBufferSize);
    uint32_t packet_id         = 0;
    io_fixture.datagram_length = kCaptureLinuxNetfilterReadBufferSize + 128U;
    require(netfilterReceivePacket(kTestSocket, buffer, &packet_id) == kNetfilterPacketDiscarded &&
                packet_id == htonl(kTestPacketId),
            "truncated packet lost its required verdict id");

    prepareReceivedPacket();
    sbufReset(buffer);
    const size_t payload_offset =
        nfqueueAttrOffset() + NFA_ALIGN(NFA_LENGTH(sizeof(struct nfqnl_msg_packet_hdr))) + NFA_LENGTH(0);
    io_fixture.message[payload_offset] = 0x65;
    require(netfilterReceivePacket(kTestSocket, buffer, &packet_id) == kNetfilterPacketMalformedDiscarded &&
                packet_id == htonl(kTestPacketId),
            "malformed IP packet lost its required verdict id");

    prepareReceivedPacket();
    sbufReset(buffer);
    ((struct nlmsghdr *) io_fixture.message)->nlmsg_type = NLMSG_NOOP;
    packet_id                                            = 77;
    require(netfilterReceivePacket(kTestSocket, buffer, &packet_id) == kNetfilterPacketError && packet_id == 77,
            "unidentified message fabricated a verdict id");
    require(io_fixture.verdict_calls == 0 && io_fixture.poll_calls == 0,
            "discard receive sent a verdict or waited for I/O");
    sbufDestroy(buffer);
}

static void testReceiveRefusalAndInterruption(void)
{
    sbuf_t   *buffer     = sbufCreate(kCaptureLinuxNetfilterReadBufferSize);
    const int failures[] = {EAGAIN, EIO};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i)
    {
        prepareReceivedPacket();
        uint32_t packet_id          = 77;
        io_fixture.receive_failures = 1;
        io_fixture.receive_errno    = failures[i];
        const netfilter_packet_result_t expected =
            failures[i] == EAGAIN ? kNetfilterPacketWouldBlock : kNetfilterPacketError;
        require(netfilterReceivePacket(kTestSocket, buffer, &packet_id) == expected && packet_id == 77,
                "receive failure changed packet ownership");
        require(io_fixture.receive_calls == 1 && io_fixture.poll_calls == 0,
                "receive failure retried or entered a wait");
    }

    prepareReceivedPacket();
    uint32_t packet_id          = 77;
    io_fixture.receive_failures = kCaptureInterruptedRetryBudget;
    io_fixture.receive_errno    = EINTR;
    require(netfilterReceivePacket(kTestSocket, buffer, &packet_id) == kNetfilterPacketYield && packet_id == 77,
            "repeated receive interruptions did not yield without consuming a packet");
    require(io_fixture.receive_calls == kCaptureInterruptedRetryBudget && io_fixture.poll_calls == 0,
            "receive interruption budget was not bounded");
    require(netfilterReceivePacket(kTestSocket, buffer, &packet_id) == kNetfilterPacketReady,
            "receive continuation could not recover after interrupted quantum");

    prepareReceivedPacket();
    sbufReset(buffer);
    io_fixture.receive_failures = 1;
    io_fixture.receive_errno    = EINTR;
    require(netfilterReceivePacket(kTestSocket, buffer, &packet_id) == kNetfilterPacketReady &&
                io_fixture.receive_calls == 2,
            "transient receive interruption did not retry");
    sbufDestroy(buffer);
}

static void testVerdictFailuresAndInterruption(void)
{
    prepareReceivedPacket();
    io_fixture.verdict_failures = kCaptureInterruptedRetryBudget;
    io_fixture.verdict_errno    = EINTR;
    require(netfilterTrySendVerdict(kTestSocket, kTestQueue, htonl(kTestPacketId), NF_DROP) == kNetfilterVerdictYield,
            "repeated verdict interruptions did not yield");
    require(io_fixture.verdict_calls == kCaptureInterruptedRetryBudget && io_fixture.poll_calls == 0,
            "verdict interruption budget was not bounded");
    require(netfilterTrySendVerdict(kTestSocket, kTestQueue, htonl(kTestPacketId), NF_DROP) == kNetfilterVerdictSent,
            "verdict continuation could not recover after interrupted quantum");

    prepareReceivedPacket();
    io_fixture.verdict_failures = 1;
    io_fixture.verdict_errno    = EINTR;
    require(netfilterTrySendVerdict(kTestSocket, kTestQueue, htonl(kTestPacketId), NF_DROP) == kNetfilterVerdictSent &&
                io_fixture.verdict_calls == 2,
            "transient verdict interruption did not retry");
    io_fixture.verdict_failures = 1;
    io_fixture.verdict_errno    = EIO;
    require(netfilterTrySendVerdict(kTestSocket, kTestQueue, htonl(kTestPacketId), NF_DROP) == kNetfilterVerdictError,
            "fatal verdict error was not reported");
    io_fixture.short_verdict = true;
    require(netfilterTrySendVerdict(kTestSocket, kTestQueue, htonl(kTestPacketId), NF_DROP) == kNetfilterVerdictError &&
                errno == EIO,
            "short Netlink send was accepted as a committed verdict");
    require(io_fixture.poll_calls == 0, "verdict failure path waited for I/O");
}

int main(void)
{
    testCaseSet("capture_linux_nfqueue_test");
    checkSumInit();
    testValidPayload(1U);
    testValidPayload(kMaxAllowedPacketLength - 1U);
    testValidPayload(kMaxAllowedPacketLength);
    testExposePayloadView();
    testCaptureLengthDiscard(kMaxAllowedPacketLength + 1U);
    testCaptureLengthDiscard(65536U);
    testPayloadAbovePolicyDiscarded();
    testDuplicateAttributesRejected();
    testShortAttributesRejected();
    testMalformedBoundsRejected();
    testCaptureLengthLessThanPayloadRejected();
    testPrefixPacketIdRecovery();
    testOpaqueCapturePayload();
    testCaptureOffloadCompletion();
    testCaptureIpv4Bounds();
    testReceiveLeavesVerdictWithCaller();
    testReceiveDiscardRetainsVerdictId();
    testReceiveRefusalAndInterruption();
    testVerdictFailuresAndInterruption();

    return 0;
}
