#include "IpOverrider/structure.h"
#include "wchecksum.h"
#include "wlibc.h"

static unsigned int forwarded_upstream;
static unsigned int forwarded_downstream;
static line_t      *forwarded_line;
static sbuf_t      *forwarded_buffer;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void recordUpstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    ++forwarded_upstream;
    forwarded_line   = l;
    forwarded_buffer = buf;
}

static void recordDownstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    ++forwarded_downstream;
    forwarded_line   = l;
    forwarded_buffer = buf;
}

static tunnel_t *createConfiguredTunnel(int chance, bool only120, cJSON **settings_out)
{
    char settings_json[1024];
    snprintf(settings_json,
             sizeof(settings_json),
             "{"
             "\"chance\":%d,"
             "\"only120\":%s,"
             "\"up\":{"
             "\"source-ip\":{\"ipv4\":[\"198.51.100.10\",\"198.51.100.11\"]},"
             "\"dest-ip\":{\"ipv4\":\"198.51.100.20\"}"
             "},"
             "\"down\":{"
             "\"source-ip\":{\"ipv4\":\"198.51.100.30\"},"
             "\"dest-ip\":{\"ipv4\":\"198.51.100.40\"}"
             "}"
             "}",
             chance,
             only120 ? "true" : "false");

    cJSON *settings = cJSON_Parse(settings_json);
    require(settings != NULL, "failed to parse IpOverrider test settings");

    node_t    node = {.node_settings_json = settings};
    tunnel_t *t    = ipoverriderCreate(&node);
    require(t != NULL, "failed to create IpOverrider test tunnel");

    *settings_out = settings;
    return t;
}

static sbuf_t *createIpv4TcpPacket(uint16_t total_len)
{
    require(total_len >= sizeof(struct ip_hdr) + sizeof(struct tcp_hdr),
            "IPv4 TCP test packet is shorter than headers");

    sbuf_t *buf = sbufCreate(512);
    require(buf != NULL, "failed to allocate IPv4 TCP packet buffer");
    sbufSetLength(buf, total_len);

    uint8_t *raw = sbufGetMutablePtr(buf);
    memoryZero(raw, total_len);

    struct ip_hdr  *ipheader  = (struct ip_hdr *) raw;
    struct tcp_hdr *tcpheader = (struct tcp_hdr *) (raw + sizeof(struct ip_hdr));

    IPH_VHL_SET(ipheader, 4, sizeof(*ipheader) / 4U);
    IPH_LEN_SET(ipheader, lwip_htons(total_len));
    IPH_TTL_SET(ipheader, 64);
    IPH_PROTO_SET(ipheader, IP_PROTO_TCP);
    ipheader->src.addr  = PP_HTONL(LWIP_MAKEU32(192, 0, 2, 1));
    ipheader->dest.addr = PP_HTONL(LWIP_MAKEU32(192, 0, 2, 2));

    tcpheader->src  = lwip_htons(12345);
    tcpheader->dest = lwip_htons(80);
    TCPH_HDRLEN_FLAGS_SET(tcpheader, sizeof(struct tcp_hdr) / 4U, TCP_ACK);

    for (size_t i = sizeof(struct ip_hdr) + sizeof(struct tcp_hdr); i < total_len; ++i)
    {
        raw[i] = (uint8_t) (i + 1);
    }

    require(calcFullPacketChecksum(raw, total_len), "failed to compute initial TCP checksums");
    return buf;
}

static sbuf_t *createIpv4UdpPacket(uint16_t total_len)
{
    require(total_len >= sizeof(struct ip_hdr) + sizeof(struct udp_hdr),
            "IPv4 UDP test packet is shorter than headers");

    sbuf_t *buf = sbufCreate(512);
    require(buf != NULL, "failed to allocate IPv4 UDP packet buffer");
    sbufSetLength(buf, total_len);

    uint8_t *raw = sbufGetMutablePtr(buf);
    memoryZero(raw, total_len);

    struct ip_hdr  *ipheader  = (struct ip_hdr *) raw;
    struct udp_hdr *udpheader = (struct udp_hdr *) (raw + sizeof(struct ip_hdr));

    IPH_VHL_SET(ipheader, 4, sizeof(*ipheader) / 4U);
    IPH_LEN_SET(ipheader, lwip_htons(total_len));
    IPH_TTL_SET(ipheader, 64);
    IPH_PROTO_SET(ipheader, IP_PROTO_UDP);
    ipheader->src.addr  = PP_HTONL(LWIP_MAKEU32(192, 0, 2, 1));
    ipheader->dest.addr = PP_HTONL(LWIP_MAKEU32(192, 0, 2, 2));

    udpheader->src  = lwip_htons(5000);
    udpheader->dest = lwip_htons(5001);
    udpheader->len  = lwip_htons((u16_t) (total_len - sizeof(struct ip_hdr)));

    for (size_t i = sizeof(struct ip_hdr) + sizeof(struct udp_hdr); i < total_len; ++i)
    {
        raw[i] = (uint8_t) (i + 10);
    }

    require(calcFullPacketChecksum(raw, total_len), "failed to compute initial UDP checksums");
    return buf;
}

static void requirePacketAddresses(sbuf_t *buf, uint32_t expected_source, uint32_t expected_dest, const char *message)
{
    const struct ip_hdr *ipheader = (const struct ip_hdr *) sbufGetRawPtr(buf);
    require(ipheader->src.addr == expected_source && ipheader->dest.addr == expected_dest, message);
}

static void bindRecordingNeighbors(tunnel_t *t, tunnel_t **prev_out, tunnel_t **next_out)
{
    tunnel_t *prev = tunnelCreate(NULL, 0, 0);
    tunnel_t *next = tunnelCreate(NULL, 0, 0);
    require(prev != NULL && next != NULL, "failed to create recording neighbors");

    prev->fnPayloadD = recordDownstream;
    next->fnPayloadU = recordUpstream;
    tunnelBind(prev, t);
    tunnelBind(t, next);

    *prev_out = prev;
    *next_out = next;
}

static void resetForwardingRecord(void)
{
    forwarded_upstream   = 0;
    forwarded_downstream = 0;
    forwarded_line       = NULL;
    forwarded_buffer     = NULL;
}

static void testChanceZeroSkipsEntireNodeAction(void)
{
    cJSON    *settings = NULL;
    tunnel_t *t        = createConfiguredTunnel(0, false, &settings);
    tunnel_t *prev     = NULL;
    tunnel_t *next     = NULL;
    bindRecordingNeighbors(t, &prev, &next);

    ipoverrider_tstate_t *state = tunnelGetState(t);
    require(state->chance == 0, "root-level chance=0 was not parsed");
    require(! state->only120, "root-level only120=false was not parsed");

    line_t  line = {0};
    sbuf_t *buf  = createIpv4TcpPacket(60);
    resetForwardingRecord();
    t->fnPayloadU(t, &line, buf);

    requirePacketAddresses(buf,
                           PP_HTONL(LWIP_MAKEU32(192, 0, 2, 1)),
                           PP_HTONL(LWIP_MAKEU32(192, 0, 2, 2)),
                           "chance=0 partially rewrote the upstream packet");
    require(! lineGetRecalculateChecksum(&line), "chance=0 modified checksum recalculation flag");
    require(atomicLoadRelaxed(&(state->rules[kIpOverriderDirectionUp][kIpOverriderModeSource].ov_4_rr_cursor)) == 0,
            "chance=0 advanced a rule's round-robin cursor");
    require(forwarded_upstream == 1 && forwarded_downstream == 0 && forwarded_line == &line && forwarded_buffer == buf,
            "chance=0 did not forward the upstream packet unchanged");
    sbufDestroy(buf);

    buf = createIpv4UdpPacket(60);
    resetForwardingRecord();
    t->fnPayloadD(t, &line, buf);

    requirePacketAddresses(buf,
                           PP_HTONL(LWIP_MAKEU32(192, 0, 2, 1)),
                           PP_HTONL(LWIP_MAKEU32(192, 0, 2, 2)),
                           "chance=0 partially rewrote the downstream packet");
    require(! lineGetRecalculateChecksum(&line), "chance=0 modified downstream checksum recalculation flag");
    require(forwarded_downstream == 1 && forwarded_upstream == 0 && forwarded_line == &line && forwarded_buffer == buf,
            "chance=0 did not forward the downstream packet unchanged");
    sbufDestroy(buf);

    /* Pre-existing true flag preserved on chance=0 */
    lineSetRecalculateChecksum(&line, true);
    buf = createIpv4TcpPacket(60);
    resetForwardingRecord();
    t->fnPayloadU(t, &line, buf);
    require(lineGetRecalculateChecksum(&line), "chance=0 cleared pre-existing recalculate_checksum flag");
    sbufDestroy(buf);

    ipoverriderDestroy(t, wwLifecycleStartupRollback());
    tunnelDestroy(next);
    tunnelDestroy(prev);
    cJSON_Delete(settings);
}

static void testCleanTcpRewriteComposition(void)
{
    cJSON    *settings = NULL;
    tunnel_t *t        = createConfiguredTunnel(100, false, &settings);
    tunnel_t *prev     = NULL;
    tunnel_t *next     = NULL;
    bindRecordingNeighbors(t, &prev, &next);

    ipoverrider_tstate_t *state    = tunnelGetState(t);
    line_t                line     = {0};
    sbuf_t               *buf      = createIpv4TcpPacket(60);
    uint32_t              new_src  = PP_HTONL(LWIP_MAKEU32(198, 51, 100, 10));
    uint32_t              new_dest = PP_HTONL(LWIP_MAKEU32(198, 51, 100, 20));

    sbuf_t        *oracle    = createIpv4TcpPacket(60);
    struct ip_hdr *oracle_ip = (struct ip_hdr *) sbufGetMutablePtr(oracle);
    oracle_ip->src.addr      = new_src;
    oracle_ip->dest.addr     = new_dest;
    require(calcFullPacketChecksum(sbufGetMutablePtr(oracle), 60), "failed to compute oracle TCP checksums");

    resetForwardingRecord();
    t->fnPayloadU(t, &line, buf);

    requirePacketAddresses(buf, new_src, new_dest, "chance=100 did not rewrite both upstream address fields");
    require(! lineGetRecalculateChecksum(&line), "incremental rewrite modified recalculate_checksum flag");
    require(atomicLoadRelaxed(&(state->rules[kIpOverriderDirectionUp][kIpOverriderModeSource].ov_4_rr_cursor)) == 1,
            "upstream rewrite did not advance its round-robin cursor exactly once");
    require(forwarded_upstream == 1 && forwarded_downstream == 0 && forwarded_line == &line && forwarded_buffer == buf,
            "chance=100 did not forward the rewritten upstream packet");

    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle), 60),
            "incrementally rewritten TCP packet mismatch with oracle");

    sbufDestroy(buf);
    sbufDestroy(oracle);
    ipoverriderDestroy(t, wwLifecycleStartupRollback());
    tunnelDestroy(next);
    tunnelDestroy(prev);
    cJSON_Delete(settings);
}

static void testCleanUdpRewriteAndZeroChecksum(void)
{
    cJSON    *settings = NULL;
    tunnel_t *t        = createConfiguredTunnel(100, false, &settings);
    tunnel_t *prev     = NULL;
    tunnel_t *next     = NULL;
    bindRecordingNeighbors(t, &prev, &next);

    line_t   line     = {0};
    sbuf_t  *buf      = createIpv4UdpPacket(60);
    uint32_t new_src  = PP_HTONL(LWIP_MAKEU32(198, 51, 100, 30));
    uint32_t new_dest = PP_HTONL(LWIP_MAKEU32(198, 51, 100, 40));

    sbuf_t        *oracle    = createIpv4UdpPacket(60);
    struct ip_hdr *oracle_ip = (struct ip_hdr *) sbufGetMutablePtr(oracle);
    oracle_ip->src.addr      = new_src;
    oracle_ip->dest.addr     = new_dest;
    require(calcFullPacketChecksum(sbufGetMutablePtr(oracle), 60), "failed to compute oracle UDP checksums");

    resetForwardingRecord();
    t->fnPayloadD(t, &line, buf);

    requirePacketAddresses(buf, new_src, new_dest, "chance=100 did not rewrite both downstream address fields");
    require(! lineGetRecalculateChecksum(&line), "downstream UDP rewrite modified recalculate_checksum flag");
    require(forwarded_downstream == 1 && forwarded_upstream == 0 && forwarded_line == &line && forwarded_buffer == buf,
            "chance=100 did not forward the rewritten downstream packet");
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle), 60),
            "incrementally rewritten UDP packet mismatch with oracle");
    sbufDestroy(buf);
    sbufDestroy(oracle);

    /* Test UDP zero checksum remains zero */
    buf                  = createIpv4UdpPacket(60);
    struct udp_hdr *udph = (struct udp_hdr *) (sbufGetMutablePtr(buf) + sizeof(struct ip_hdr));
    udph->chksum         = 0;
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(buf), 60), "failed to compute IP header checksum");

    resetForwardingRecord();
    t->fnPayloadD(t, &line, buf);

    requirePacketAddresses(buf, new_src, new_dest, "downstream zero-UDP rewrite failed");
    udph = (struct udp_hdr *) (sbufGetMutablePtr(buf) + sizeof(struct ip_hdr));
    require(udph->chksum == 0, "zero UDP checksum was modified to non-zero");
    require(! lineGetRecalculateChecksum(&line), "zero UDP rewrite modified recalculate_checksum flag");
    sbufDestroy(buf);

    ipoverriderDestroy(t, wwLifecycleStartupRollback());
    tunnelDestroy(next);
    tunnelDestroy(prev);
    cJSON_Delete(settings);
}

static void testExistingFullRecalculationRequestPreserved(void)
{
    cJSON    *settings = NULL;
    tunnel_t *t        = createConfiguredTunnel(100, false, &settings);
    tunnel_t *prev     = NULL;
    tunnel_t *next     = NULL;
    bindRecordingNeighbors(t, &prev, &next);

    line_t line = {0};
    lineSetRecalculateChecksum(&line, true);

    sbuf_t  *buf      = createIpv4TcpPacket(60);
    uint32_t new_src  = PP_HTONL(LWIP_MAKEU32(198, 51, 100, 10));
    uint32_t new_dest = PP_HTONL(LWIP_MAKEU32(198, 51, 100, 20));

    sbuf_t *expected_intermediate = sbufCreate(512);
    sbufSetLength(expected_intermediate, 60);
    memoryCopy(sbufGetMutablePtr(expected_intermediate), sbufGetRawPtr(buf), 60);
    setIpv4AddressWithChecksumUpdate(sbufGetMutablePtr(expected_intermediate), 60, kIpv4ChecksumAddressSource, new_src);
    setIpv4AddressWithChecksumUpdate(
        sbufGetMutablePtr(expected_intermediate), 60, kIpv4ChecksumAddressDestination, new_dest);

    resetForwardingRecord();
    t->fnPayloadU(t, &line, buf);

    require(lineGetRecalculateChecksum(&line), "pre-existing recalculate_checksum flag was cleared");
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(expected_intermediate), 60),
            "incremental helper was not applied to pending-recalculation packet");

    /* Simulating a later full recalculation */
    require(calcFullPacketChecksum(sbufGetMutablePtr(buf), 60), "later full recalculation failed");
    sbuf_t        *oracle    = createIpv4TcpPacket(60);
    struct ip_hdr *oracle_ip = (struct ip_hdr *) sbufGetMutablePtr(oracle);
    oracle_ip->src.addr      = new_src;
    oracle_ip->dest.addr     = new_dest;
    require(calcFullPacketChecksum(sbufGetMutablePtr(oracle), 60), "oracle calc failed");
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle), 60),
            "later full recalculation mismatch with oracle");

    sbufDestroy(buf);
    sbufDestroy(expected_intermediate);
    sbufDestroy(oracle);
    ipoverriderDestroy(t, wwLifecycleStartupRollback());
    tunnelDestroy(next);
    tunnelDestroy(prev);
    cJSON_Delete(settings);
}

static void testOnly120GatesEntireNodeAction(void)
{
    cJSON    *settings = NULL;
    tunnel_t *t        = createConfiguredTunnel(100, true, &settings);
    tunnel_t *prev     = NULL;
    tunnel_t *next     = NULL;
    bindRecordingNeighbors(t, &prev, &next);

    ipoverrider_tstate_t *state = tunnelGetState(t);
    require(state->only120, "root-level only120=true was not parsed");

    line_t line = {0};

    /* Upstream oversized (121 bytes) -> skipped */
    sbuf_t *buf = createIpv4TcpPacket(121);
    resetForwardingRecord();
    t->fnPayloadU(t, &line, buf);

    requirePacketAddresses(buf,
                           PP_HTONL(LWIP_MAKEU32(192, 0, 2, 1)),
                           PP_HTONL(LWIP_MAKEU32(192, 0, 2, 2)),
                           "only120 partially rewrote an oversized upstream packet");
    require(! lineGetRecalculateChecksum(&line), "only120 modified checksum recalculation flag for oversized packet");
    require(atomicLoadRelaxed(&(state->rules[kIpOverriderDirectionUp][kIpOverriderModeSource].ov_4_rr_cursor)) == 0,
            "only120 advanced a rule's round-robin cursor for an oversized packet");
    require(forwarded_upstream == 1 && forwarded_downstream == 0 && forwarded_line == &line && forwarded_buffer == buf,
            "only120 did not forward the oversized upstream packet unchanged");
    sbufDestroy(buf);

    /* Upstream boundary (120 bytes) -> rewritten */
    buf = createIpv4TcpPacket(120);
    resetForwardingRecord();
    t->fnPayloadU(t, &line, buf);

    requirePacketAddresses(buf,
                           PP_HTONL(LWIP_MAKEU32(198, 51, 100, 10)),
                           PP_HTONL(LWIP_MAKEU32(198, 51, 100, 20)),
                           "only120 did not rewrite both fields at the 120-byte boundary");
    require(! lineGetRecalculateChecksum(&line), "only120 boundary rewrite modified checksum flag");
    require(atomicLoadRelaxed(&(state->rules[kIpOverriderDirectionUp][kIpOverriderModeSource].ov_4_rr_cursor)) == 1,
            "only120 boundary rewrite did not advance the round-robin cursor");
    sbufDestroy(buf);

    /* Downstream oversized (121 bytes) -> skipped */
    buf = createIpv4UdpPacket(121);
    resetForwardingRecord();
    t->fnPayloadD(t, &line, buf);

    requirePacketAddresses(buf,
                           PP_HTONL(LWIP_MAKEU32(192, 0, 2, 1)),
                           PP_HTONL(LWIP_MAKEU32(192, 0, 2, 2)),
                           "only120 partially rewrote an oversized downstream packet");
    require(! lineGetRecalculateChecksum(&line),
            "only120 modified checksum recalculation flag for oversized downstream packet");
    require(forwarded_downstream == 1 && forwarded_upstream == 0 && forwarded_line == &line && forwarded_buffer == buf,
            "only120 did not forward the oversized downstream packet unchanged");
    sbufDestroy(buf);

    /* Downstream boundary (120 bytes) -> rewritten */
    buf = createIpv4UdpPacket(120);
    resetForwardingRecord();
    t->fnPayloadD(t, &line, buf);

    requirePacketAddresses(buf,
                           PP_HTONL(LWIP_MAKEU32(198, 51, 100, 30)),
                           PP_HTONL(LWIP_MAKEU32(198, 51, 100, 40)),
                           "only120 did not rewrite downstream fields at the 120-byte boundary");
    require(! lineGetRecalculateChecksum(&line), "only120 downstream boundary rewrite modified checksum flag");
    sbufDestroy(buf);

    ipoverriderDestroy(t, wwLifecycleStartupRollback());
    tunnelDestroy(next);
    tunnelDestroy(prev);
    cJSON_Delete(settings);
}

static void testUnchangedAddressHandling(void)
{
    cJSON    *settings = NULL;
    tunnel_t *t        = createConfiguredTunnel(100, false, &settings);
    tunnel_t *prev     = NULL;
    tunnel_t *next     = NULL;
    bindRecordingNeighbors(t, &prev, &next);

    ipoverrider_tstate_t *state       = tunnelGetState(t);
    line_t                line        = {0};
    uint32_t              target_src  = PP_HTONL(LWIP_MAKEU32(198, 51, 100, 10));
    uint32_t              target_dest = PP_HTONL(LWIP_MAKEU32(198, 51, 100, 20));

    sbuf_t        *buf      = createIpv4TcpPacket(60);
    struct ip_hdr *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);
    ipheader->src.addr      = target_src;
    ipheader->dest.addr     = target_dest;
    require(calcFullPacketChecksum(sbufGetMutablePtr(buf), 60), "failed to compute initial checksums");

    sbuf_t *before = sbufCreate(512);
    sbufSetLength(before, 60);
    memoryCopy(sbufGetMutablePtr(before), sbufGetRawPtr(buf), 60);

    resetForwardingRecord();
    t->fnPayloadU(t, &line, buf);

    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(before), 60), "unchanged address packet was modified");
    require(! lineGetRecalculateChecksum(&line), "unchanged address modified recalculate_checksum flag");
    require(atomicLoadRelaxed(&(state->rules[kIpOverriderDirectionUp][kIpOverriderModeSource].ov_4_rr_cursor)) == 1,
            "unchanged source address did not advance the round-robin cursor exactly once");
    require(forwarded_upstream == 1 && forwarded_downstream == 0 && forwarded_line == &line && forwarded_buffer == buf,
            "unchanged address forwarding failed");

    sbufDestroy(buf);
    sbufDestroy(before);
    ipoverriderDestroy(t, wwLifecycleStartupRollback());
    tunnelDestroy(next);
    tunnelDestroy(prev);
    cJSON_Delete(settings);
}

static void testRejectionAndMalformedPackets(void)
{
    cJSON    *settings = NULL;
    tunnel_t *t        = createConfiguredTunnel(100, false, &settings);
    tunnel_t *prev     = NULL;
    tunnel_t *next     = NULL;
    bindRecordingNeighbors(t, &prev, &next);

    line_t line = {0};

    /* 1. IPv6 packet (IPH_V = 6) - with false and true flags */
    sbuf_t *buf = sbufCreate(256);
    sbufSetLength(buf, 40);
    uint8_t *raw = sbufGetMutablePtr(buf);
    memoryZero(raw, 40);
    raw[0] = 0x60; /* IPv6 version */
    uint8_t before6[40];
    memoryCopy(before6, raw, 40);

    resetForwardingRecord();
    t->fnPayloadU(t, &line, buf);
    require(memoryEqual(sbufGetRawPtr(buf), before6, 40), "IPv6 packet was modified");
    require(! lineGetRecalculateChecksum(&line), "IPv6 packet modified checksum flag");
    require(forwarded_upstream == 1 && forwarded_downstream == 0, "IPv6 packet forwarding failed");
    sbufDestroy(buf);

    buf = sbufCreate(256);
    sbufSetLength(buf, 40);
    raw = sbufGetMutablePtr(buf);
    memoryZero(raw, 40);
    raw[0] = 0x60;
    lineSetRecalculateChecksum(&line, true);
    resetForwardingRecord();
    t->fnPayloadU(t, &line, buf);
    require(memoryEqual(sbufGetRawPtr(buf), before6, 40), "IPv6 packet was modified");
    require(lineGetRecalculateChecksum(&line), "pre-existing true flag cleared on IPv6 packet");
    sbufDestroy(buf);

    /* 2. Truncated IPv4 header (length < 20) - with false and true flags */
    lineSetRecalculateChecksum(&line, false);
    buf = sbufCreate(256);
    sbufSetLength(buf, 10);
    raw = sbufGetMutablePtr(buf);
    memoryZero(raw, 10);
    uint8_t before_trunc[10];
    memoryCopy(before_trunc, raw, 10);

    resetForwardingRecord();
    t->fnPayloadU(t, &line, buf);
    require(memoryEqual(sbufGetRawPtr(buf), before_trunc, 10), "truncated packet was modified");
    require(! lineGetRecalculateChecksum(&line), "truncated packet modified checksum flag");
    require(forwarded_upstream == 1 && forwarded_downstream == 0, "truncated packet forwarding failed");
    sbufDestroy(buf);

    buf = sbufCreate(256);
    sbufSetLength(buf, 10);
    raw = sbufGetMutablePtr(buf);
    memoryZero(raw, 10);
    lineSetRecalculateChecksum(&line, true);
    resetForwardingRecord();
    t->fnPayloadU(t, &line, buf);
    require(memoryEqual(sbufGetRawPtr(buf), before_trunc, 10), "truncated packet was modified");
    require(lineGetRecalculateChecksum(&line), "pre-existing true flag cleared on truncated packet");
    sbufDestroy(buf);

    /* 3. Malformed TCP header (data offset = 4 < 5) */
    lineSetRecalculateChecksum(&line, false);
    buf                  = createIpv4TcpPacket(60);
    struct tcp_hdr *tcph = (struct tcp_hdr *) (sbufGetMutablePtr(buf) + sizeof(struct ip_hdr));
    TCPH_HDRLEN_FLAGS_SET(tcph, 4, TCP_ACK); /* short data offset */
    sbuf_t *before_tcp = sbufCreate(512);
    sbufSetLength(before_tcp, 60);
    memoryCopy(sbufGetMutablePtr(before_tcp), sbufGetRawPtr(buf), 60);

    resetForwardingRecord();
    t->fnPayloadU(t, &line, buf);
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(before_tcp), 60), "malformed TCP packet was modified");
    require(! lineGetRecalculateChecksum(&line), "malformed TCP packet modified checksum flag");
    require(forwarded_upstream == 1 && forwarded_downstream == 0 && forwarded_line == &line && forwarded_buffer == buf,
            "malformed TCP packet was not forwarded upstream exactly once");
    sbufDestroy(buf);

    buf  = createIpv4TcpPacket(60);
    tcph = (struct tcp_hdr *) (sbufGetMutablePtr(buf) + sizeof(struct ip_hdr));
    TCPH_HDRLEN_FLAGS_SET(tcph, 4, TCP_ACK);
    lineSetRecalculateChecksum(&line, true);
    resetForwardingRecord();
    t->fnPayloadU(t, &line, buf);
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(before_tcp), 60), "malformed TCP packet was modified");
    require(lineGetRecalculateChecksum(&line), "pre-existing true flag cleared on malformed TCP packet");
    require(forwarded_upstream == 1 && forwarded_downstream == 0 && forwarded_line == &line && forwarded_buffer == buf,
            "malformed TCP packet with a pending checksum request was not forwarded upstream exactly once");
    sbufDestroy(buf);
    sbufDestroy(before_tcp);

    /* 4. Malformed UDP header (udp_len = 4 < UDP_HLEN) */
    lineSetRecalculateChecksum(&line, false);
    buf                  = createIpv4UdpPacket(60);
    struct udp_hdr *udph = (struct udp_hdr *) (sbufGetMutablePtr(buf) + sizeof(struct ip_hdr));
    udph->len            = lwip_htons(4); /* < UDP_HLEN */
    sbuf_t *before_udp   = sbufCreate(512);
    sbufSetLength(before_udp, 60);
    memoryCopy(sbufGetMutablePtr(before_udp), sbufGetRawPtr(buf), 60);

    resetForwardingRecord();
    t->fnPayloadD(t, &line, buf);
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(before_udp), 60), "malformed UDP packet was modified");
    require(! lineGetRecalculateChecksum(&line), "malformed UDP packet modified checksum flag");
    require(forwarded_downstream == 1 && forwarded_upstream == 0 && forwarded_line == &line && forwarded_buffer == buf,
            "malformed UDP packet was not forwarded downstream exactly once");
    sbufDestroy(buf);

    buf       = createIpv4UdpPacket(60);
    udph      = (struct udp_hdr *) (sbufGetMutablePtr(buf) + sizeof(struct ip_hdr));
    udph->len = lwip_htons(4);
    lineSetRecalculateChecksum(&line, true);
    resetForwardingRecord();
    t->fnPayloadD(t, &line, buf);
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(before_udp), 60), "malformed UDP packet was modified");
    require(lineGetRecalculateChecksum(&line), "pre-existing true flag cleared on malformed UDP packet");
    require(forwarded_downstream == 1 && forwarded_upstream == 0 && forwarded_line == &line && forwarded_buffer == buf,
            "malformed UDP packet with a pending checksum request was not forwarded downstream exactly once");
    sbufDestroy(buf);
    sbufDestroy(before_udp);

    ipoverriderDestroy(t, wwLifecycleStartupRollback());
    tunnelDestroy(next);
    tunnelDestroy(prev);
    cJSON_Delete(settings);
}

int main(void)
{
    checkSumInit();
    testChanceZeroSkipsEntireNodeAction();
    testCleanTcpRewriteComposition();
    testCleanUdpRewriteAndZeroChecksum();
    testExistingFullRecalculationRequestPreserved();
    testOnly120GatesEntireNodeAction();
    testUnchangedAddressHandling();
    testRejectionAndMalformedPackets();
    return 0;
}
