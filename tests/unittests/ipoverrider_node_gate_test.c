#include "IpOverrider/structure.h"

#include <stdio.h>
#include <stdlib.h>

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

static sbuf_t *createIpv4Packet(uint16_t total_len)
{
    require(total_len >= sizeof(struct ip_hdr), "IPv4 test packet is shorter than its header");

    sbuf_t *buf = sbufCreate(256);
    require(buf != NULL, "failed to allocate IPv4 packet buffer");
    sbufSetLength(buf, total_len);

    struct ip_hdr *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);
    memoryZero(ipheader, total_len);
    IPH_VHL_SET(ipheader, 4, sizeof(*ipheader) / 4U);
    IPH_LEN_SET(ipheader, lwip_htons(total_len));
    ipheader->src.addr  = PP_HTONL(LWIP_MAKEU32(192, 0, 2, 1));
    ipheader->dest.addr = PP_HTONL(LWIP_MAKEU32(192, 0, 2, 2));
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
    sbuf_t *buf  = createIpv4Packet(60);
    resetForwardingRecord();
    t->fnPayloadU(t, &line, buf);

    requirePacketAddresses(buf,
                           PP_HTONL(LWIP_MAKEU32(192, 0, 2, 1)),
                           PP_HTONL(LWIP_MAKEU32(192, 0, 2, 2)),
                           "chance=0 partially rewrote the upstream packet");
    require(! lineGetRecalculateChecksum(&line), "chance=0 requested checksum recalculation");
    require(atomicLoadRelaxed(&(state->rules[kIpOverriderDirectionUp][kIpOverriderModeSource].ov_4_rr_cursor)) == 0,
            "chance=0 advanced a rule's round-robin cursor");
    require(forwarded_upstream == 1 && forwarded_downstream == 0 && forwarded_line == &line && forwarded_buffer == buf,
            "chance=0 did not forward the upstream packet unchanged");
    sbufDestroy(buf);

    buf = createIpv4Packet(60);
    resetForwardingRecord();
    t->fnPayloadD(t, &line, buf);

    requirePacketAddresses(buf,
                           PP_HTONL(LWIP_MAKEU32(192, 0, 2, 1)),
                           PP_HTONL(LWIP_MAKEU32(192, 0, 2, 2)),
                           "chance=0 partially rewrote the downstream packet");
    require(! lineGetRecalculateChecksum(&line), "chance=0 requested downstream checksum recalculation");
    require(forwarded_downstream == 1 && forwarded_upstream == 0 && forwarded_line == &line && forwarded_buffer == buf,
            "chance=0 did not forward the downstream packet unchanged");
    sbufDestroy(buf);

    ipoverriderDestroy(t);
    tunnelDestroy(next);
    tunnelDestroy(prev);
    cJSON_Delete(settings);
}

static void testChanceHundredAppliesEntireNodeAction(void)
{
    cJSON    *settings = NULL;
    tunnel_t *t        = createConfiguredTunnel(100, false, &settings);
    tunnel_t *prev     = NULL;
    tunnel_t *next     = NULL;
    bindRecordingNeighbors(t, &prev, &next);

    ipoverrider_tstate_t *state = tunnelGetState(t);
    require(state->chance == 100, "root-level chance=100 was not parsed");
    require(! state->only120, "root-level only120=false was not parsed");

    line_t  line = {0};
    sbuf_t *buf  = createIpv4Packet(60);
    resetForwardingRecord();
    t->fnPayloadU(t, &line, buf);

    requirePacketAddresses(buf,
                           PP_HTONL(LWIP_MAKEU32(198, 51, 100, 10)),
                           PP_HTONL(LWIP_MAKEU32(198, 51, 100, 20)),
                           "chance=100 did not rewrite both upstream address fields");
    require(lineGetRecalculateChecksum(&line), "upstream rewrite did not request checksum recalculation");
    require(atomicLoadRelaxed(&(state->rules[kIpOverriderDirectionUp][kIpOverriderModeSource].ov_4_rr_cursor)) == 1,
            "upstream rewrite did not advance its round-robin cursor exactly once");
    require(forwarded_upstream == 1 && forwarded_downstream == 0 && forwarded_line == &line && forwarded_buffer == buf,
            "chance=100 did not forward the rewritten upstream packet");
    sbufDestroy(buf);

    lineSetRecalculateChecksum(&line, false);
    buf = createIpv4Packet(60);
    resetForwardingRecord();
    t->fnPayloadD(t, &line, buf);

    requirePacketAddresses(buf,
                           PP_HTONL(LWIP_MAKEU32(198, 51, 100, 30)),
                           PP_HTONL(LWIP_MAKEU32(198, 51, 100, 40)),
                           "chance=100 did not rewrite both downstream address fields");
    require(lineGetRecalculateChecksum(&line), "downstream rewrite did not request checksum recalculation");
    require(forwarded_downstream == 1 && forwarded_upstream == 0 && forwarded_line == &line && forwarded_buffer == buf,
            "chance=100 did not forward the rewritten downstream packet");
    sbufDestroy(buf);

    ipoverriderDestroy(t);
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

    line_t  line = {0};
    sbuf_t *buf  = createIpv4Packet(121);
    resetForwardingRecord();
    t->fnPayloadU(t, &line, buf);

    requirePacketAddresses(buf,
                           PP_HTONL(LWIP_MAKEU32(192, 0, 2, 1)),
                           PP_HTONL(LWIP_MAKEU32(192, 0, 2, 2)),
                           "only120 partially rewrote an oversized upstream packet");
    require(! lineGetRecalculateChecksum(&line), "only120 requested checksum recalculation for an oversized packet");
    require(atomicLoadRelaxed(&(state->rules[kIpOverriderDirectionUp][kIpOverriderModeSource].ov_4_rr_cursor)) == 0,
            "only120 advanced a rule's round-robin cursor for an oversized packet");
    require(forwarded_upstream == 1 && forwarded_downstream == 0 && forwarded_line == &line && forwarded_buffer == buf,
            "only120 did not forward the oversized upstream packet unchanged");
    sbufDestroy(buf);

    buf = createIpv4Packet(120);
    resetForwardingRecord();
    t->fnPayloadU(t, &line, buf);

    requirePacketAddresses(buf,
                           PP_HTONL(LWIP_MAKEU32(198, 51, 100, 10)),
                           PP_HTONL(LWIP_MAKEU32(198, 51, 100, 20)),
                           "only120 did not rewrite both fields at the 120-byte boundary");
    require(lineGetRecalculateChecksum(&line), "only120 boundary rewrite did not request checksum recalculation");
    require(atomicLoadRelaxed(&(state->rules[kIpOverriderDirectionUp][kIpOverriderModeSource].ov_4_rr_cursor)) == 1,
            "only120 boundary rewrite did not advance the round-robin cursor");
    sbufDestroy(buf);

    lineSetRecalculateChecksum(&line, false);
    buf = createIpv4Packet(121);
    resetForwardingRecord();
    t->fnPayloadD(t, &line, buf);

    requirePacketAddresses(buf,
                           PP_HTONL(LWIP_MAKEU32(192, 0, 2, 1)),
                           PP_HTONL(LWIP_MAKEU32(192, 0, 2, 2)),
                           "only120 partially rewrote an oversized downstream packet");
    require(! lineGetRecalculateChecksum(&line),
            "only120 requested downstream checksum recalculation for an oversized packet");
    require(forwarded_downstream == 1 && forwarded_upstream == 0 && forwarded_line == &line && forwarded_buffer == buf,
            "only120 did not forward the oversized downstream packet unchanged");
    sbufDestroy(buf);

    buf = createIpv4Packet(120);
    resetForwardingRecord();
    t->fnPayloadD(t, &line, buf);

    requirePacketAddresses(buf,
                           PP_HTONL(LWIP_MAKEU32(198, 51, 100, 30)),
                           PP_HTONL(LWIP_MAKEU32(198, 51, 100, 40)),
                           "only120 did not rewrite both downstream fields at the 120-byte boundary");
    require(lineGetRecalculateChecksum(&line),
            "only120 downstream boundary rewrite did not request checksum recalculation");
    sbufDestroy(buf);

    ipoverriderDestroy(t);
    tunnelDestroy(next);
    tunnelDestroy(prev);
    cJSON_Delete(settings);
}

int main(void)
{
    testChanceZeroSkipsEntireNodeAction();
    testChanceHundredAppliesEntireNodeAction();
    testOnly120GatesEntireNodeAction();
    return 0;
}
