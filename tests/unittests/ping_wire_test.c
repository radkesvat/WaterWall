#include "PingCommon/ping_wire.h"
#include "wwapi.h"

enum
{
    kTestInnerProtocol = 253,
    kTestIdentifier    = 0x1234,
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "ASSERT FAILED: %s\n", message);
        exit(1);
    }
}

static uint32_t ipv4Address(const char *text)
{
    ip4_addr_t address = {0};
    require(ip4AddrAddressToNetwork(text, &address) != 0, "test IPv4 parsing failed");
    return ip4AddrGetU32(&address);
}

static sbuf_t *makeInnerPacket(uint16_t length, uint16_t offset)
{
    require(length >= IP_HLEN, "test inner packet is too short");

    sbuf_t *buf = sbufCreateWithPadding(length, kPingWireEncapsulationOverhead);
    sbufSetLength(buf, length);
    memoryZero(sbufGetMutablePtr(buf), length);

    struct ip_hdr *ip = (struct ip_hdr *) sbufGetMutablePtr(buf);
    IPH_VHL_SET(ip, 4, IP_HLEN / 4U);
    IPH_TOS_SET(ip, 7);
    IPH_LEN_SET(ip, lwip_htons(length));
    IPH_ID_SET(ip, lwip_htons(0x8877));
    IPH_OFFSET_SET(ip, offset);
    IPH_TTL_SET(ip, 55);
    IPH_PROTO_SET(ip, kTestInnerProtocol);
    ip->src.addr  = ipv4Address("10.10.0.1");
    ip->dest.addr = ipv4Address("10.10.0.2");

    for (uint16_t i = IP_HLEN; i < length; ++i)
    {
        sbufGetMutablePtr(buf)[i] = (uint8_t) (i * 13U + 9U);
    }
    require(calcFullPacketChecksum(sbufGetMutablePtr(buf), length), "test inner checksum failed");
    return buf;
}

static void requireValidChecksums(const sbuf_t *buf)
{
    const uint8_t       *packet = sbufGetRawPtr(buf);
    const struct ip_hdr *ip     = (const struct ip_hdr *) packet;
    const uint16_t       hlen   = IPH_HL_BYTES(ip);
    const uint16_t       total  = lwip_ntohs(IPH_LEN(ip));

    require(total == sbufGetLength(buf), "outer total length does not equal buffer length");
    require(inet_chksum(packet, hlen) == 0, "outer IPv4 checksum is invalid");
    require(inet_chksum(packet + hlen, (uint16_t) (total - hlen)) == 0, "outer ICMP checksum is invalid");
}

static const struct icmp_echo_hdr *icmpHeader(const sbuf_t *buf)
{
    return (const struct icmp_echo_hdr *) ((const uint8_t *) sbufGetRawPtr(buf) + kPingWireIpv4HeaderLength);
}

static void testRequestSequenceMatrix(void)
{
    const ping_wire_config_t config = {
        .local_ipv4 = ipv4Address("192.0.2.40"),
        .peer_ipv4  = ipv4Address("198.51.100.40"),
        .identifier = kTestIdentifier,
        .ttl        = 61,
        .tos        = 11,
    };
    const uint16_t sequences[] = {1, 2, UINT16_MAX, 0};
    uint16_t       identifier  = 0;

    require(pingwireSelectIdentifier(false, 0, 0x9999, &identifier) && identifier == 0,
            "explicit zero identifier override changed");
    require(pingwireSelectIdentifier(false, UINT16_MAX, 0, &identifier) && identifier == UINT16_MAX,
            "explicit maximum identifier override changed");
    require(! pingwireSelectIdentifier(true, 0, 0, &identifier), "random identifier accepted a zero candidate");
    require(pingwireSelectIdentifier(true, 0, 0x4321, &identifier) && identifier == 0x4321,
            "random identifier candidate was not selected deterministically");

    for (size_t i = 0; i < ARRAY_SIZE(sequences); ++i)
    {
        sbuf_t *request = makeInnerPacket(72, 0);
        require(pingwireEchoRequestPreflight(request), "preflight rejected a buildable request");
        require(pingwireBuildEchoRequest(request, &config, sequences[i]), "sequence-matrix request build failed");
        requireValidChecksums(request);

        const struct icmp_echo_hdr *icmp = icmpHeader(request);
        require(icmp->type == ICMP_ECHO && icmp->code == 0, "sequence-matrix request type/code is wrong");
        require(lwip_ntohs(icmp->id) == kTestIdentifier, "deterministic identifier override changed");
        require(lwip_ntohs(icmp->seqno) == sequences[i], "request sequence did not preserve modulo-16-bit value");
        sbufDestroy(request);
    }
}

static void testRequestAndReply(void)
{
    const ping_wire_config_t client = {
        .local_ipv4 = ipv4Address("192.0.2.10"),
        .peer_ipv4  = ipv4Address("198.51.100.10"),
        .identifier = kTestIdentifier,
        .ttl        = 64,
        .tos        = 16,
    };
    const ping_wire_config_t server = {
        .local_ipv4 = client.peer_ipv4,
        .peer_ipv4  = client.local_ipv4,
        .identifier = 0x9999,
        .ttl        = 47,
        .tos        = 0,
    };

    sbuf_t *request = makeInnerPacket(96, 0);
    uint8_t original[96];
    memoryCopy(original, sbufGetRawPtr(request), sizeof(original));

    require(pingwireBuildEchoRequest(request, &client, 1), "request builder rejected valid input");
    require(sbufGetLength(request) == sizeof(original) + kPingWireEncapsulationOverhead,
            "request output length is wrong");
    requireValidChecksums(request);

    const uint8_t              *request_bytes = sbufGetRawPtr(request);
    const struct ip_hdr        *outer         = (const struct ip_hdr *) request_bytes;
    const struct icmp_echo_hdr *icmp = (const struct icmp_echo_hdr *) (request_bytes + kPingWireIpv4HeaderLength);
    require(IPH_TOS(outer) == client.tos, "request TOS is wrong");
    require(IPH_TTL(outer) == client.ttl, "request TTL is wrong");
    require(IPH_ID(outer) == 0, "DF request IPv4 ID is not zero");
    require(lwip_ntohs(IPH_OFFSET(outer)) == IP_DF, "request DF policy is wrong");
    require(outer->src.addr == client.local_ipv4 && outer->dest.addr == client.peer_ipv4,
            "request addresses are wrong");
    require(icmp->type == ICMP_ECHO && icmp->code == 0, "request ICMP type/code is wrong");
    require(lwip_ntohs(icmp->id) == client.identifier && lwip_ntohs(icmp->seqno) == 1,
            "request identifier or first sequence is wrong");
    require(memoryEqual(request_bytes + kPingWireEncapsulationOverhead, original, sizeof(original)),
            "request altered the inner IPv4 packet");

    ping_wire_envelope_t request_view = {0};
    require(pingwireParseInbound(sbufGetRawPtr(request), sbufGetLength(request), &server, &request_view) ==
                kPingWireInboundEchoRequest,
            "receiver did not parse a valid Echo Request");

    sbuf_t *reply = sbufDuplicate(request);
    require(pingwireBuildEchoReply(reply, &server, &request_view, 0x4321), "reply builder rejected valid request");
    requireValidChecksums(reply);

    const uint8_t              *reply_bytes = sbufGetRawPtr(reply);
    const struct ip_hdr        *reply_outer = (const struct ip_hdr *) reply_bytes;
    const struct icmp_echo_hdr *reply_icmp  = (const struct icmp_echo_hdr *) (reply_bytes + kPingWireIpv4HeaderLength);
    require(reply_icmp->type == ICMP_ER && reply_icmp->code == 0, "reply ICMP type/code is wrong");
    require(reply_icmp->id == icmp->id && reply_icmp->seqno == icmp->seqno, "reply did not mirror identifier/sequence");
    require(reply_outer->src.addr == server.local_ipv4 && reply_outer->dest.addr == server.peer_ipv4,
            "reply did not reverse addresses");
    require(IPH_TOS(reply_outer) == client.tos && IPH_TTL(reply_outer) == server.ttl, "reply TOS/TTL policy is wrong");
    require(lwip_ntohs(IPH_OFFSET(reply_outer)) == 0, "reply fragmentation flags are not clear");
    require(lwip_ntohs(IPH_ID(reply_outer)) == 0x4321, "reply IPv4 ID is wrong");
    require(memoryEqual(reply_bytes + kPingWireEncapsulationOverhead,
                        request_bytes + kPingWireEncapsulationOverhead,
                        sizeof(original)),
            "reply did not mirror the exact ICMP payload");

    sbufDestroy(reply);
    sbufDestroy(request);
}

static void testCorrelationAndReplay(void)
{
    const ping_wire_config_t client = {
        .local_ipv4 = ipv4Address("192.0.2.10"),
        .peer_ipv4  = ipv4Address("198.51.100.10"),
        .identifier = kTestIdentifier,
        .ttl        = 64,
        .tos        = 0,
    };
    const ping_wire_config_t server = {
        .local_ipv4 = client.peer_ipv4,
        .peer_ipv4  = client.local_ipv4,
        .identifier = 0x9999,
        .ttl        = 64,
        .tos        = 0,
    };
    uint8_t digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE];
    for (uint32_t i = 0; i < sizeof(digest_key); ++i)
    {
        digest_key[i] = (uint8_t) (i + 1U);
    }

    ping_wire_tracker_t *tracker = pingwireTrackerCreate();
    require(tracker != NULL, "tracker construction failed");

    sbuf_t *request = makeInnerPacket(88, 0);
    require(pingwireBuildEchoRequest(request, &client, 65535), "request builder rejected correlation input");
    const uint8_t *payload = (const uint8_t *) sbufGetRawPtr(request) + kPingWireEncapsulationOverhead;
    require(pingwireOutstandingRecord(tracker,
                                      digest_key,
                                      client.identifier,
                                      65535,
                                      client.peer_ipv4,
                                      client.local_ipv4,
                                      payload,
                                      (uint16_t) (sbufGetLength(request) - kPingWireEncapsulationOverhead)),
            "outstanding record failed");

    ping_wire_envelope_t request_view = {0};
    require(pingwireParseInbound(sbufGetRawPtr(request), sbufGetLength(request), &server, &request_view) ==
                kPingWireInboundEchoRequest,
            "request did not parse for replay test");
    require(pingwireReplayMark(tracker, digest_key, &request_view) == kPingWireReplayNew,
            "first peer request was not recorded");
    require(pingwireReplayMark(tracker, digest_key, &request_view) == kPingWireReplayDuplicate,
            "duplicate peer request was not recognized");

    sbuf_t *reply = sbufDuplicate(request);
    require(pingwireBuildEchoReply(reply, &server, &request_view, 1), "reply build failed in correlation test");
    ping_wire_envelope_t reply_view = {0};
    require(pingwireParseInbound(sbufGetRawPtr(reply), sbufGetLength(reply), &client, &reply_view) ==
                kPingWireInboundEchoReply,
            "reply did not parse for correlation test");

    ping_wire_envelope_t mismatch = reply_view;
    mismatch.type                 = ICMP_ECHO;
    require(! pingwireOutstandingConsume(tracker, digest_key, &mismatch),
            "wrong reply type consumed an outstanding entry");
    mismatch      = reply_view;
    mismatch.code = 1;
    require(! pingwireOutstandingConsume(tracker, digest_key, &mismatch),
            "wrong reply code consumed an outstanding entry");
    mismatch            = reply_view;
    mismatch.identifier = (uint16_t) (reply_view.identifier + 1U);
    require(! pingwireOutstandingConsume(tracker, digest_key, &mismatch),
            "wrong reply identifier consumed an outstanding entry");
    mismatch          = reply_view;
    mismatch.sequence = (uint16_t) (reply_view.sequence + 1U);
    require(! pingwireOutstandingConsume(tracker, digest_key, &mismatch),
            "wrong reply sequence consumed an outstanding entry");
    mismatch             = reply_view;
    mismatch.source_ipv4 = client.local_ipv4;
    require(! pingwireOutstandingConsume(tracker, digest_key, &mismatch),
            "wrong reply source consumed an outstanding entry");
    mismatch                  = reply_view;
    mismatch.destination_ipv4 = client.peer_ipv4;
    require(! pingwireOutstandingConsume(tracker, digest_key, &mismatch),
            "wrong reply destination consumed an outstanding entry");
    mismatch                     = reply_view;
    mismatch.icmp_payload_length = (uint16_t) (reply_view.icmp_payload_length - 1U);
    require(! pingwireOutstandingConsume(tracker, digest_key, &mismatch),
            "wrong reply length consumed an outstanding entry");

    sbuf_t *wrong_payload = sbufDuplicate(reply);
    sbufGetMutablePtr(wrong_payload)[kPingWireEncapsulationOverhead] ^= 1U;
    require(calcFullPacketChecksum(sbufGetMutablePtr(wrong_payload), sbufGetLength(wrong_payload)),
            "failed to recompute altered reply checksum");
    ping_wire_envelope_t wrong_payload_view = {0};
    require(pingwireParseInbound(
                sbufGetRawPtr(wrong_payload), sbufGetLength(wrong_payload), &client, &wrong_payload_view) ==
                kPingWireInboundEchoReply,
            "altered but checksummed reply did not parse");
    require(! pingwireOutstandingConsume(tracker, digest_key, &wrong_payload_view),
            "payload-mismatched reply consumed an outstanding entry");
    sbufDestroy(wrong_payload);

    sbuf_t *bad_checksum = sbufDuplicate(reply);
    sbufGetMutablePtr(bad_checksum)[kPingWireEncapsulationOverhead] ^= 1U;
    require(
        pingwireParseInbound(sbufGetRawPtr(bad_checksum), sbufGetLength(bad_checksum), &client, &wrong_payload_view) ==
            kPingWireInboundInvalidCarrier,
        "checksum-invalid reply was accepted");
    sbufDestroy(bad_checksum);

    sbuf_t *bad_ipv4_checksum = sbufDuplicate(reply);
    sbufGetMutablePtr(bad_ipv4_checksum)[8] ^= 1U;
    require(pingwireParseInbound(
                sbufGetRawPtr(bad_ipv4_checksum), sbufGetLength(bad_ipv4_checksum), &client, &wrong_payload_view) ==
                kPingWireInboundMalformed,
            "IPv4-checksum-invalid reply was accepted");
    sbufDestroy(bad_ipv4_checksum);

    sbuf_t        *fragmented_outer = sbufDuplicate(reply);
    struct ip_hdr *fragmented_ip    = (struct ip_hdr *) sbufGetMutablePtr(fragmented_outer);
    IPH_OFFSET_SET(fragmented_ip, lwip_htons(IP_MF));
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(fragmented_outer), sbufGetLength(fragmented_outer)),
            "failed to recompute fragmented outer header checksum");
    require(pingwireParseInbound(
                sbufGetRawPtr(fragmented_outer), sbufGetLength(fragmented_outer), &client, &wrong_payload_view) ==
                kPingWireInboundInvalidCarrier,
            "fragmented outer envelope was accepted");
    sbufDestroy(fragmented_outer);

    require(pingwireOutstandingConsume(tracker, digest_key, &reply_view),
            "exact reply did not consume outstanding entry");
    require(! pingwireOutstandingConsume(tracker, digest_key, &reply_view), "same reply consumed twice");

    sbufDestroy(reply);
    sbufDestroy(request);
    pingwireTrackerDestroy(tracker);
    memorySecureZero(digest_key, sizeof(digest_key));
}

static void testBoundsFragmentsAndIdPolicy(void)
{
    const ping_wire_config_t config = {
        .local_ipv4 = ipv4Address("203.0.113.1"),
        .peer_ipv4  = ipv4Address("203.0.113.2"),
        .identifier = 7,
        .ttl        = 64,
        .tos        = 0,
    };

    sbuf_t *maximum = makeInnerPacket(kPingWireMaxInnerPacketLength, lwip_htons(IP_MF));
    require(pingwireBuildEchoRequest(maximum, &config, 3), "maximum valid inner fragment was rejected");
    require(sbufGetLength(maximum) == kMaxAllowedPacketLength, "maximum carrier length is wrong");
    sbufDestroy(maximum);

    sbuf_t *oversize = makeInnerPacket(kPingWireMaxInnerPacketLength + 1U, 0);
    require(! pingwireEchoRequestPreflight(oversize), "oversized request passed preflight");
    require(! pingwireBuildEchoRequest(oversize, &config, 3), "oversized inner packet was accepted");
    sbufDestroy(oversize);

    sbuf_t *short_padding = sbufCreateWithPadding(96, 0);
    sbufSetLength(short_padding, 96);
    memoryZero(sbufGetMutablePtr(short_padding), 96);
    struct ip_hdr *short_ip = (struct ip_hdr *) sbufGetMutablePtr(short_padding);
    IPH_VHL_SET(short_ip, 4, IP_HLEN / 4U);
    IPH_LEN_SET(short_ip, lwip_htons(96));
    IPH_TTL_SET(short_ip, 64);
    IPH_PROTO_SET(short_ip, kTestInnerProtocol);
    require(calcFullPacketChecksum(sbufGetMutablePtr(short_padding), 96), "short-padding inner checksum failed");
    require(! pingwireEchoRequestPreflight(short_padding), "short-padding request passed preflight");
    require(! pingwireBuildEchoRequest(short_padding, &config, 4), "insufficient padding was accepted");
    sbufDestroy(short_padding);

    sbuf_t *ipv6 = sbufCreateWithPadding(40, kPingWireEncapsulationOverhead);
    sbufSetLength(ipv6, 40);
    memoryZero(sbufGetMutablePtr(ipv6), 40);
    sbufGetMutablePtr(ipv6)[0] = 0x60;
    require(! pingwireEchoRequestPreflight(ipv6), "IPv6 input passed request preflight");
    sbufDestroy(ipv6);

    ping_wire_reply_id_generator_t ids;
    pingwireReplyIdGeneratorInitialize(&ids, 0x0000fffeU, 100);
    require(pingwireReplyIdGeneratorNextAt(&ids, 101, 0) == 0xffff, "reply ID did not advance monotonically");
    require(pingwireReplyIdGeneratorNextAt(&ids, 102, 0) == 0, "reply ID did not wrap at 16 bits");
    require(pingwireReplyIdGeneratorNextAt(&ids, 1202, 0) == 2,
            "idle perturbation did not advance the reply ID before reservation");

    pingwireReplyIdGeneratorInitialize(&ids, 10, 100);
    require(pingwireReplyIdGeneratorNextAt(&ids, 1200, kPingWireReplyPerturbationMaximum) == 43,
            "maximum idle perturbation exceeded or missed its bound");
}

static void testMalformedEnvelopeMatrix(void)
{
    const ping_wire_config_t sender = {
        .local_ipv4 = ipv4Address("192.0.2.60"),
        .peer_ipv4  = ipv4Address("198.51.100.60"),
        .identifier = 0x6060,
        .ttl        = 64,
        .tos        = 0,
    };
    const ping_wire_config_t receiver = {
        .local_ipv4 = sender.peer_ipv4,
        .peer_ipv4  = sender.local_ipv4,
        .identifier = 0x7070,
        .ttl        = 64,
        .tos        = 0,
    };
    ping_wire_envelope_t envelope = {0};

    uint8_t truncated_ipv4[IP_HLEN - 1U] = {0};
    truncated_ipv4[0]                    = 0x45;
    require(pingwireParseInbound(truncated_ipv4, sizeof(truncated_ipv4), &receiver, &envelope) ==
                kPingWireInboundMalformed,
            "truncated IPv4 header was accepted");

    sbuf_t *request = makeInnerPacket(80, 0);
    require(pingwireBuildEchoRequest(request, &sender, 9), "malformed-matrix request build failed");

    sbuf_t *trailing = sbufCreateWithPadding(sbufGetLength(request) + 1U, kPingWireEncapsulationOverhead);
    sbufSetLength(trailing, sbufGetLength(request) + 1U);
    memoryCopy(sbufGetMutablePtr(trailing), sbufGetRawPtr(request), sbufGetLength(request));
    sbufGetMutablePtr(trailing)[sbufGetLength(request)] = 0;
    require(pingwireParseInbound(sbufGetRawPtr(trailing), sbufGetLength(trailing), &receiver, &envelope) ==
                kPingWireInboundMalformed,
            "carrier with trailing bytes was accepted");
    sbufDestroy(trailing);

    sbuf_t        *short_icmp = sbufCreateWithPadding(IP_HLEN + 4U, kPingWireEncapsulationOverhead);
    struct ip_hdr *short_ip   = (struct ip_hdr *) sbufGetMutablePtr(short_icmp);
    sbufSetLength(short_icmp, IP_HLEN + 4U);
    memoryZero(short_ip, IP_HLEN + 4U);
    IPH_VHL_SET(short_ip, 4, IP_HLEN / 4U);
    IPH_LEN_SET(short_ip, lwip_htons(IP_HLEN + 4U));
    IPH_TTL_SET(short_ip, 64);
    IPH_PROTO_SET(short_ip, IP_PROTO_ICMP);
    short_ip->src.addr  = receiver.peer_ipv4;
    short_ip->dest.addr = receiver.local_ipv4;
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(short_icmp), sbufGetLength(short_icmp)),
            "short-ICMP IPv4 checksum build failed");
    require(pingwireParseInbound(sbufGetRawPtr(short_icmp), sbufGetLength(short_icmp), &receiver, &envelope) ==
                kPingWireInboundInvalidCarrier,
            "truncated ICMP header was accepted");
    sbufDestroy(short_icmp);

    sbuf_t        *outer_fragment = sbufDuplicate(request);
    struct ip_hdr *fragment_ip    = (struct ip_hdr *) sbufGetMutablePtr(outer_fragment);
    IPH_OFFSET_SET(fragment_ip, lwip_htons(IP_MF));
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(outer_fragment), sbufGetLength(outer_fragment)),
            "fragmented carrier checksum build failed");
    require(pingwireParseInbound(sbufGetRawPtr(outer_fragment), sbufGetLength(outer_fragment), &receiver, &envelope) ==
                kPingWireInboundInvalidCarrier,
            "fragmented outer carrier was accepted");
    sbufDestroy(outer_fragment);

    sbufDestroy(request);
}

int main(void)
{
    initWLibc();
    checkSumInit();
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");

    testRequestAndReply();
    testRequestSequenceMatrix();
    testCorrelationAndReplay();
    testBoundsFragmentsAndIdPolicy();
    testMalformedEnvelopeMatrix();

    wCryptoGlobalCleanup();
    return 0;
}
