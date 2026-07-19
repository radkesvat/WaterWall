#include "devices/capture/capture_linux_internal.h"

#include <arpa/inet.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

enum
{
    kTestPacketId = 0x10203040U
};

typedef struct nfqueue_message_builder_s
{
    uint8_t        *data;
    size_t          capacity;
    struct nlmsghdr *nlh;
} nfqueue_message_builder_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

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

static struct nfattr *nfqueueBuilderAppendAttr(nfqueue_message_builder_t *builder, uint16_t type,
                                               const void *payload, uint16_t payload_len)
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

    return nfqueueBuilderAppendAttr(
        builder, NFQA_PACKET_HDR, &packet_hdr, (uint16_t) sizeof(packet_hdr));
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
    uint8_t                       message[kCaptureLinuxNetfilterReadBufferSize];
    uint8_t                       payload[16];
    nfqueue_message_builder_t     builder;
    netfilter_packet_view_t       view;
    struct nfqnl_msg_packet_hdr   packet_hdr;
    uint32_t                      cap_len = htonl((uint32_t) sizeof(payload));

    fillPayload(payload, sizeof(payload));
    memoryZero(&packet_hdr, sizeof(packet_hdr));
    packet_hdr.packet_id = htonl(kTestPacketId);

    nfqueueBuilderInit(&builder, message, sizeof(message));
    nfqueueBuilderAppendAttr(
        &builder, NFQA_PACKET_HDR, &packet_hdr, (uint16_t) (sizeof(packet_hdr) - 1U));
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
    payload_attr = nfqueueBuilderAppendPayload(&builder, payload, (uint16_t) sizeof(payload));
    payload_attr->nfa_len = (uint16_t) NFA_LENGTH(200);
    require(parseBuilt(&builder, &view) == kNetfilterPacketParseMalformed,
            "attribute extending beyond message accepted");
    require(view.has_packet_id, "oversized attribute lost packet id");

    nfqueueBuilderInit(&builder, message, sizeof(message));
    nfqueueBuilderAppendPacketHeader(&builder);
    payload_attr = nfqueueBuilderAppendPayload(&builder, payload, (uint16_t) sizeof(payload));
    original_len = nfqueueBuilderLen(&builder);
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
    require(captureLinuxNetfilterTryReadPacketIdFromPrefix(
                message, complete_packet_header_prefix, &packet_id),
            "complete prefix did not recover packet id");
    require(packet_id == htonl(kTestPacketId), "prefix packet id byte order changed");

    packet_id = 0;
    require(! captureLinuxNetfilterTryReadPacketIdFromPrefix(
                message, nfqueueAttrOffset() + sizeof(struct nfattr) + 1U, &packet_id),
            "incomplete packet header prefix produced a packet id");
}

int main(void)
{
    testValidPayload(1U);
    testValidPayload(1499U);
    testValidPayload(1500U);
    testExposePayloadView();
    testCaptureLengthDiscard(1501U);
    testCaptureLengthDiscard(65536U);
    testPayloadAbovePolicyDiscarded();
    testDuplicateAttributesRejected();
    testShortAttributesRejected();
    testMalformedBoundsRejected();
    testCaptureLengthLessThanPayloadRejected();
    testPrefixPacketIdRecovery();

    return 0;
}
