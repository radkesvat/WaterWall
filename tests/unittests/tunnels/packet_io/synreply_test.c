/*
 * Exercises the real SynReply callbacks between two in-memory packet neighbours
 * on chain-owned worker lines. Covers opening-SYN classification, wire replies,
 * unchanged buffer handoff, strict settings and synchronous lifecycle reentry.
 * CTest: waterwall.synreply_unit
 */
#include "SynReply/interface.h"

#include "fixtures/worker_registry_fixture.h"
#include "loggers/internal_logger.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

enum
{
    kWorkers      = 2,
    kReplyLength  = IP_HLEN + TCP_HLEN,
    kSenderPort   = 54321,
    kListenerPort = 443,
    kHeadroom     = 96
};

static const uint32_t kSender       = UINT32_C(0xc633641e); /* 198.51.100.30 */
static const uint32_t kFirstTarget  = UINT32_C(0xc000020a); /* 192.0.2.10 */
static const uint32_t kSecondTarget = UINT32_C(0xc000020b); /* 192.0.2.11 */
static const uint32_t kOverride     = UINT32_C(0xc0000214); /* 192.0.2.20 */

typedef struct packet_s
{
    uint8_t bytes[64];
    size_t  length;
    bool    repair;
} packet_t;

typedef enum event_kind_e
{
    kOriginal,
    kReply,
    kInit,
    kEst,
    kPause,
    kResume,
    kFinish
} event_kind_t;

typedef struct event_s
{
    event_kind_t kind;
    bool         upstream;
} event_t;

static struct fixture_s
{
    test_worker_registry_t registry;
    master_pool_t         *large;
    master_pool_t         *medium;
    master_pool_t         *small;
    buffer_pool_t         *pools[kWorkers];
    tunnel_chain_t        *chain;
    node_t                 head;
    node_t                 node;
    node_t                 tail;
    tunnel_t              *prev;
    tunnel_t              *synreply;
    tunnel_t              *next;
    event_t                trace[16];
    size_t                 trace_length;
    const packet_t        *incoming;
    sbuf_t                *incoming_buffer;
    bool                   incoming_upstream;
    packet_t               reply;
    const packet_t        *nested_syn;
    bool                   finish_during_payload;
} fixture;

static void recordEvent(tunnel_t *t, const line_t *line, event_kind_t kind)
{
    require(t == fixture.prev || t == fixture.next, "callback reached an unexpected tunnel");
    require(lineIsOnCurrentWorker(line) && lineIsAlive(line) && tunnelchainIsWorkerPacketLine(fixture.chain, line),
            "callback did not use the live chain packet line on its worker");
    require(fixture.trace_length < ARRAY_SIZE(fixture.trace), "trace overflow");
    fixture.trace[fixture.trace_length++] = (event_t) {.kind = kind, .upstream = t == fixture.next};
}

static void requireTrace(const event_t *expected, size_t count)
{
    require(fixture.trace_length == count, "wrong number of callbacks");
    for (size_t i = 0; i < count; ++i)
    {
        require(fixture.trace[i].kind == expected[i].kind && fixture.trace[i].upstream == expected[i].upstream,
                "wrong callback kind, direction or order");
    }
}

static void recordInit(tunnel_t *t, line_t *line)
{
    recordEvent(t, line, kInit);
}

static void recordEst(tunnel_t *t, line_t *line)
{
    recordEvent(t, line, kEst);
}

static void recordPause(tunnel_t *t, line_t *line)
{
    recordEvent(t, line, kPause);
}

static void recordResume(tunnel_t *t, line_t *line)
{
    recordEvent(t, line, kResume);
}

static void recordFinish(tunnel_t *t, line_t *line)
{
    recordEvent(t, line, kFinish);
    require(! tunnelIsActiveForLine(fixture.synreply, line),
            "Finish reached a neighbour before SynReply bypassed the line");
}

static void sendPacket(line_t *line, const packet_t *packet, bool upstream)
{
    require(fixture.incoming == NULL, "nested input began before its caller transferred ownership");
    /* Keep the original in a different size tier so the reply cannot reuse its allocation. */
    sbuf_t *buf = bufferpoolGetMediumBuffer(lineGetBufferPool(line));
    sbufSetLength(buf, packet->length);
    memoryCopy(sbufGetMutablePtr(buf), packet->bytes, packet->length);
    sbufSetRecalculateChecksum(buf, packet->repair);
    fixture.incoming          = packet;
    fixture.incoming_buffer   = buf;
    fixture.incoming_upstream = upstream;

    if (upstream)
        tunnelNextUpStreamPayload(fixture.prev, line, buf);
    else
        tunnelPrevDownStreamPayload(fixture.next, line, buf);

    require(fixture.incoming == NULL, "original packet was not forwarded");
}

static void recordPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    if (fixture.incoming != NULL)
    {
        const packet_t *expected = fixture.incoming;
        recordEvent(t, line, kOriginal);
        require((t == fixture.next) == fixture.incoming_upstream, "original packet changed directions");
        require(buf == fixture.incoming_buffer, "original buffer identity changed");
        require(sbufGetLength(buf) == expected->length &&
                    memoryEqual(sbufGetRawPtr(buf), expected->bytes, expected->length),
                "original packet bytes changed");
        require(sbufGetRecalculateChecksum(buf) == expected->repair, "original checksum-repair flag changed");
        fixture.incoming        = NULL;
        fixture.incoming_buffer = NULL;

        /* A synchronous consumer can overwrite and recycle the original before returning. */
        memorySet(sbufGetMutablePtr(buf), 0xa5, expected->length);
        lineReuseBuffer(line, buf);

        if (fixture.nested_syn)
        {
            const packet_t *nested = fixture.nested_syn;
            fixture.nested_syn     = NULL;
            sendPacket(line, nested, true);
        }
        else if (fixture.finish_during_payload)
        {
            fixture.finish_during_payload = false;
            tunnelPrevDownStreamFinish(t, line);
        }
        return;
    }

    recordEvent(t, line, kReply);
    require(t == fixture.prev, "generated reply did not go downstream");
    require(! sbufIsSplice(buf) && sbufGetLength(buf) == kReplyLength,
            "reply was not a minimal ordinary IPv4/TCP packet");
    buffer_pool_t *pool = lineGetBufferPool(line);
    require(sbufGetTotalCapacityNoPadding(buf) == bufferpoolGetSmallBufferSize(pool) &&
                sbufGetHeadroom(buf) == bufferpoolGetSmallBufferPadding(pool) && sbufGetHeadroom(buf) >= kHeadroom,
            "reply did not use the worker's ordinary small-buffer capacity and headroom");
    require(! sbufGetRecalculateChecksum(buf), "reply requested checksum repair");
    memoryCopy(fixture.reply.bytes, sbufGetRawPtr(buf), kReplyLength);
    lineReuseBuffer(line, buf);
}

static void setupWorkers(void)
{
    fixture.large  = masterpoolCreateWithCapacity(16);
    fixture.medium = masterpoolCreateWithCapacity(16);
    fixture.small  = masterpoolCreateWithCapacity(16);
    require(fixture.large != NULL && fixture.medium != NULL && fixture.small != NULL, "master pool creation failed");
    GSTATE.workers_count         = kWorkers;
    GSTATE.ram_profile           = 1;
    GSTATE.shortcut_buffer_pools = fixture.pools;
    testWorkerRegistryInstall(&fixture.registry);
    for (wid_t wid = 0; wid < kWorkers; ++wid)
    {
        testWorkerBindWID(wid);
        fixture.pools[wid] =
            bufferpoolCreate(fixture.large, fixture.medium, fixture.small, 4, 4096, 2048, 512, 4096, 4096);
        require(fixture.pools[wid] != NULL, "worker buffer pool creation failed");
        GSTATE.workers[wid].buffer_pool = fixture.pools[wid];
    }
    testWorkerBindWID(0);
}

static void teardownWorkers(void)
{
    for (wid_t wid = 0; wid < kWorkers; ++wid)
    {
        testWorkerBindWID(wid);
        bufferpoolDestroy(fixture.pools[wid]);
    }
    testWorkerUnbindWID();
    testWorkerRegistryRestore(&fixture.registry);
    GSTATE.workers_count         = 0;
    GSTATE.ram_profile           = 0;
    GSTATE.shortcut_buffer_pools = NULL;
    masterpoolMakeEmpty(fixture.large);
    masterpoolMakeEmpty(fixture.medium);
    masterpoolMakeEmpty(fixture.small);
    masterpoolDestroy(fixture.large);
    masterpoolDestroy(fixture.medium);
    masterpoolDestroy(fixture.small);
}

static void loadSettings(node_t *node, const char *settings)
{
    *node      = nodeSynReplyGet();
    node->name = (char *) "synreply";
    if (settings)
    {
        node->node_settings_json = cJSON_Parse(settings);
        require(node->node_settings_json != NULL, "settings fixture did not parse");
    }
}

static void deleteSettings(node_t *node)
{
    cJSON_Delete(node->node_settings_json);
    memoryFree(node->type);
}

static void setupChain(const char *settings)
{
    fixture.head = (node_t) {.name                  = (char *) "head",
                             .type                  = (char *) "PacketHead",
                             .flags                 = kNodeFlagChainHead,
                             .layer_group           = kNodeLayer3,
                             .layer_group_next_node = kNodeLayer3,
                             .layer_group_prev_node = kNodeLayerNone,
                             .can_have_next         = true,
                             .required_padding_left = kHeadroom};
    fixture.tail = (node_t) {.name                  = (char *) "tail",
                             .type                  = (char *) "PacketTail",
                             .flags                 = kNodeFlagChainEnd,
                             .layer_group           = kNodeLayer3,
                             .layer_group_next_node = kNodeLayerNone,
                             .layer_group_prev_node = kNodeLayer3,
                             .can_have_prev         = true};
    loadSettings(&fixture.node, settings);
    require(fixture.node.required_padding_left == 0 && fixture.node.layer_group == kNodeLayer3 &&
                fixture.node.layer_group_prev_node == kNodeLayer3 &&
                fixture.node.layer_group_next_node == kNodeLayer3 && fixture.node.can_have_prev &&
                fixture.node.can_have_next,
            "SynReply advertised the wrong middle-node metadata");
    fixture.prev     = packettunnelCreate(&fixture.head, 0, 0);
    fixture.synreply = fixture.node.createHandle(&fixture.node);
    fixture.next     = packettunnelCreate(&fixture.tail, 0, 0);
    require(fixture.prev && fixture.synreply && fixture.next, "packet tunnel construction failed");

    fixture.prev->fnPayloadD = fixture.next->fnPayloadU = recordPayload;
    fixture.prev->fnInitD = fixture.next->fnInitU = recordInit;
    fixture.prev->fnEstD = fixture.next->fnEstU = recordEst;
    fixture.prev->fnPauseD = fixture.next->fnPauseU = recordPause;
    fixture.prev->fnResumeD = fixture.next->fnResumeU = recordResume;
    fixture.prev->fnFinD = fixture.next->fnFinU = recordFinish;
    tunnelBind(fixture.prev, fixture.synreply);
    tunnelBind(fixture.synreply, fixture.next);

    fixture.chain = tunnelchainCreate(kWorkers);
    tunnelchainInsert(fixture.chain, fixture.prev);
    tunnelchainInsert(fixture.chain, fixture.synreply);
    tunnelchainInsert(fixture.chain, fixture.next);
    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(fixture.chain, &status), status.message);
    require(fixture.chain->contains_packet_node, "chain was not classified as Layer 3");
    uint32_t offset = 0;
    for (uint16_t i = 0; i < fixture.chain->tunnels.len; ++i)
    {
        tunnel_t *t = fixture.chain->tunnels.tuns[i];
        t->onIndex(t, i, &offset);
    }
    tunnelchainFinalize(fixture.chain);
    require(fixture.chain->finalized, "chain finalization failed");
}

static void teardownChain(void)
{
    testWorkerBindWID(0);
    fixture.synreply->onDestroy(fixture.synreply, wwLifecycleStartupRollback());
    tunnelDestroy(fixture.next);
    tunnelDestroy(fixture.prev);
    tunnelchainDestroy(fixture.chain);
    deleteSettings(&fixture.node);
}

static packet_t makeTcpPacket(uint32_t destination, uint32_t sequence, uint8_t flags, bool options,
                              uint8_t payload_length)
{
    const uint8_t option_length = options ? 4 : 0;
    const uint8_t ip_length     = IP_HLEN + option_length;
    const uint8_t tcp_length    = TCP_HLEN + option_length;
    packet_t      packet        = {.length = (size_t) ip_length + tcp_length + payload_length};
    require(packet.length <= sizeof(packet.bytes), "TCP fixture overflow");
    uint8_t *ip  = packet.bytes;
    uint8_t *tcp = ip + ip_length;
    ip[0]        = (uint8_t) (0x40 | (ip_length / 4));
    PUT_BE16(ip + 2, (uint16_t) packet.length);
    ip[8] = 64;
    ip[9] = IPPROTO_TCP;
    PUT_BE32(ip + 12, kSender);
    PUT_BE32(ip + 16, destination);
    PUT_BE16(tcp, kSenderPort);
    PUT_BE16(tcp + 2, kListenerPort);
    PUT_BE32(tcp + 4, sequence);
    tcp[12] = (uint8_t) ((tcp_length / 4) << 4);
    tcp[13] = flags;
    PUT_BE16(tcp + 14, 4096);
    if (options)
    {
        const uint8_t ip_options[]  = {0x1e, 4, 0x56, 0x78};
        const uint8_t tcp_options[] = {0xfd, 3, 0xa5, 1};
        memoryCopy(ip + IP_HLEN, ip_options, sizeof(ip_options));
        memoryCopy(tcp + TCP_HLEN, tcp_options, sizeof(tcp_options));
    }
    memorySet(tcp + tcp_length, 0x33, payload_length);
    require(calcFullPacketChecksum(ip, packet.length), "TCP fixture checksum generation failed");
    return packet;
}

/* Fold network-order words including the stored checksum to get the residual. */
static uint16_t checksumResidual(const uint8_t *bytes, size_t length)
{
    uint32_t sum = 0;
    for (size_t offset = 0; offset < length; offset += 2)
        sum += GET_BE16(bytes + offset);
    while (sum >> 16)
        sum = (sum & UINT16_MAX) + (sum >> 16);
    return (uint16_t) ~sum;
}

static void requireReply(uint32_t source, uint32_t sequence)
{
    const uint8_t *ip  = fixture.reply.bytes;
    const uint8_t *tcp = ip + IP_HLEN;
    require(ip[0] == 0x45 && GET_BE16(ip + 2) == kReplyLength && ip[8] > 0 && ip[9] == IPPROTO_TCP,
            "reply IPv4 header is wrong");
    require((GET_BE16(ip + 6) & (UINT16_C(0x8000) | IP_MF | IP_OFFMASK)) == 0,
            "reply was fragmented or used the reserved IPv4 flag");
    require(GET_BE32(ip + 12) == source && GET_BE32(ip + 16) == kSender, "reply addresses are wrong");
    require(GET_BE16(tcp) == kListenerPort && GET_BE16(tcp + 2) == kSenderPort, "reply ports did not reverse");
    require(GET_BE32(tcp + 8) == sequence + UINT32_C(1), "reply acknowledgment is wrong");
    require(tcp[12] == 0x50 && tcp[13] == (TCP_SYN | TCP_ACK) && GET_BE16(tcp + 14) > 0 && GET_BE16(tcp + 18) == 0,
            "reply TCP header is wrong");
    require(checksumResidual(ip, IP_HLEN) == 0, "IPv4 reply checksum residual is nonzero");
    uint8_t tcp_checksum_input[12 + TCP_HLEN] = {0};
    memoryCopy(tcp_checksum_input, ip + 12, 8);
    tcp_checksum_input[9] = IPPROTO_TCP;
    PUT_BE16(tcp_checksum_input + 10, TCP_HLEN);
    memoryCopy(tcp_checksum_input + 12, tcp, TCP_HLEN);
    require(checksumResidual(tcp_checksum_input, sizeof(tcp_checksum_input)) == 0,
            "TCP reply checksum residual is nonzero");
}

static void checkOpeningSyn(line_t *line, const packet_t *syn, uint32_t source, uint32_t sequence)
{
    const event_t expected[] = {{kOriginal, true}, {kReply, false}};
    fixture.trace_length     = 0;
    sendPacket(line, syn, true);
    requireTrace(expected, ARRAY_SIZE(expected));
    requireReply(source, sequence);
}

static void checkPassThrough(const char *name, line_t *line, const packet_t *packet, bool upstream)
{
    testCaseSet(name);
    const event_t expected[] = {{kOriginal, upstream}};
    fixture.trace_length     = 0;
    sendPacket(line, packet, upstream);
    requireTrace(expected, ARRAY_SIZE(expected));
}

static void checkNonUnicastEndpoints(line_t *line)
{
    static const struct
    {
        uint32_t    address;
        const char *source_case;
        const char *destination_case;
    } cases[] = {
        {UINT32_C(0xe0000001), "multicast SYN source", "multicast SYN destination"},
        {UINT32_MAX, "limited broadcast SYN source", "limited broadcast SYN destination"},
        {0, "unspecified SYN source", "unspecified SYN destination"},
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        packet_t packet = makeTcpPacket(cases[i].address, 150, TCP_SYN, false, 0);
        checkPassThrough(cases[i].destination_case, line, &packet, true);
        PUT_BE32(packet.bytes + 12, cases[i].address);
        PUT_BE32(packet.bytes + 16, kFirstTarget);
        require(calcFullPacketChecksum(packet.bytes, packet.length), "source address fixture checksum failed");
        checkPassThrough(cases[i].source_case, line, &packet, true);
    }
}

static void checkSourceSetting(const char *settings, bool overridden)
{
    testCaseSet(settings ? settings : "settings omitted");
    setupChain(settings);
    line_t        *line   = tunnelchainGetWorkerPacketLine(fixture.chain, 0);
    const packet_t first  = makeTcpPacket(kFirstTarget, 150, TCP_SYN, false, 0);
    const packet_t second = makeTcpPacket(kSecondTarget, 151, TCP_SYN, false, 0);
    checkOpeningSyn(line, &first, overridden ? kOverride : kFirstTarget, 150);
    checkOpeningSyn(line, &second, overridden ? kOverride : kSecondTarget, 151);
    checkNonUnicastEndpoints(line);
    teardownChain();
}

static void checkInvalidSettings(void)
{
    static const char *const invalid[] = {
        "null",
        "[]",
        "{\"reply_source_ip\":null}",
        "{\"reply_source_ip\":42}",
        "{\"reply_source_ip\":\"\"}",
        "{\"reply_source_ip\":\"localhost\"}",
        "{\"reply_source_ip\":\"2001:db8::1\"}",
        "{\"reply_source_ip\":\"192.0.2.20/32\"}",
        "{\"reply_source_ip\":\"192.0.2.256\"}",
        "{\"reply_source_ip\":\"224.0.0.1\"}",
        "{\"reply_source_ip\":\"255.255.255.255\"}",
        "{\"reply_source_ip\":\"0.0.0.0\"}",
        "{\"reply_src_ip\":\"192.0.2.20\"}",
        "{\"reply_source_ip\":\"192.0.2.20\",\"reply_source_ip\":\"192.0.2.21\"}",
        "{\"reply_source_ip\":\"192.0.2.20\\u0000suffix\"}",
        "{\"reply_source_ip\\u0000suffix\":\"192.0.2.20\"}",
    };
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
    {
        testCaseSet(invalid[i]);
        node_t node;
        loadSettings(&node, invalid[i]);
        require(node.createHandle(&node) == NULL, "malformed settings constructed a tunnel");
        deleteSettings(&node);
    }
}

static void checkOpeningPackets(line_t *line)
{
    testCaseSet("retransmissions");
    const packet_t syn = makeTcpPacket(kFirstTarget, 7493, TCP_SYN, false, 0);
    checkOpeningSyn(line, &syn, kFirstTarget, 7493);
    checkOpeningSyn(line, &syn, kFirstTarget, 7493);

    testCaseSet("IPv4 and TCP options, ECN, and acknowledgment wraparound");
    packet_t ecn = makeTcpPacket(kSecondTarget, UINT32_MAX, TCP_SYN | TCP_ECE | TCP_CWR, true, 0);
    checkOpeningSyn(line, &ecn, kSecondTarget, UINT32_MAX);
    testCaseSet("valid bytes with pending checksum repair");
    ecn.repair = true;
    checkOpeningSyn(line, &ecn, kSecondTarget, UINT32_MAX);
}

static void checkPassThroughPackets(line_t *line)
{
    const packet_t syn = makeTcpPacket(kFirstTarget, 7493, TCP_SYN, false, 0);
    checkPassThrough("downstream SYN", line, &syn, false);
    packet_t packet = makeTcpPacket(kFirstTarget, 7494, TCP_ACK, false, 0);
    checkPassThrough("subsequent ACK", line, &packet, true);
    packet = makeTcpPacket(kFirstTarget, 7493, TCP_SYN | TCP_ACK, false, 0);
    checkPassThrough("upstream SYN-ACK", line, &packet, true);
    checkPassThrough("downstream SYN-ACK", line, &packet, false);
    packet = makeTcpPacket(kFirstTarget, 7493, TCP_SYN, false, 4);
    checkPassThrough("SYN with payload", line, &packet, true);

    packet = (packet_t) {.length = 40 + TCP_HLEN, .bytes = {0x60}};
    PUT_BE16(packet.bytes + 4, TCP_HLEN);
    packet.bytes[6] = IPPROTO_TCP;
    packet.bytes[7] = 64;
    packet.bytes[8] = packet.bytes[24] = 0x20;
    packet.bytes[9] = packet.bytes[25] = 0x01;
    packet.bytes[23]                   = 1;
    packet.bytes[39]                   = 2;
    memoryCopy(packet.bytes + 40, syn.bytes + IP_HLEN, TCP_HLEN);
    PUT_BE16(packet.bytes + 40 + 16, 0);
    uint8_t ipv6_checksum_input[40 + TCP_HLEN] = {0};
    memoryCopy(ipv6_checksum_input, packet.bytes + 8, 32);
    PUT_BE32(ipv6_checksum_input + 32, TCP_HLEN);
    ipv6_checksum_input[39] = IPPROTO_TCP;
    memoryCopy(ipv6_checksum_input + 40, packet.bytes + 40, TCP_HLEN);
    PUT_BE16(packet.bytes + 40 + 16, checksumResidual(ipv6_checksum_input, sizeof(ipv6_checksum_input)));
    checkPassThrough("IPv6 TCP SYN", line, &packet, true);

    packet        = syn;
    packet.length = IP_HLEN + UDP_HLEN;
    PUT_BE16(packet.bytes + 2, (uint16_t) packet.length);
    packet.bytes[9] = IPPROTO_UDP;
    PUT_BE16(packet.bytes + IP_HLEN + 4, UDP_HLEN);
    require(calcFullPacketChecksum(packet.bytes, packet.length), "UDP fixture checksum generation failed");
    checkPassThrough("UDP", line, &packet, true);

    packet = makeTcpPacket(kFirstTarget, 7493, TCP_SYN, true, 0);
    PUT_BE16(packet.bytes + 6, IP_MF);
    require(calcIpv4HeaderChecksum(packet.bytes, packet.length), "first fragment IPv4 checksum failed");
    checkPassThrough("first fragment", line, &packet, true);
    PUT_BE16(packet.bytes + 6, 3);
    require(calcIpv4HeaderChecksum(packet.bytes, packet.length), "later fragment IPv4 checksum failed");
    checkPassThrough("later fragment", line, &packet, true);
}

static void checkMalformedPackets(line_t *line)
{
    const packet_t syn    = makeTcpPacket(kFirstTarget, 7493, TCP_SYN, false, 0);
    packet_t       packet = syn;
    packet.length         = IP_HLEN - 1;
    checkPassThrough("truncated IPv4 header", line, &packet, true);
    packet.length = syn.length - 1;
    checkPassThrough("truncated TCP header", line, &packet, true);
    packet.length = syn.length + 1;
    checkPassThrough("trailing bytes after IPv4 total length", line, &packet, true);

    packet          = syn;
    packet.bytes[0] = 0x44;
    checkPassThrough("invalid IPv4 header length", line, &packet, true);
    packet                     = syn;
    packet.bytes[IP_HLEN + 12] = 0x60;
    checkPassThrough("invalid TCP header length", line, &packet, true);

    const packet_t options    = makeTcpPacket(kFirstTarget, 7493, TCP_SYN, true, 0);
    packet                    = options;
    packet.bytes[IP_HLEN + 1] = 5;
    require(calcFullPacketChecksum(packet.bytes, packet.length), "invalid IPv4 option fixture checksum failed");
    checkPassThrough("IPv4 option overruns header", line, &packet, true);
    packet                                   = options;
    packet.bytes[IP_HLEN + 4 + TCP_HLEN + 1] = 1;
    require(calcFullPacketChecksum(packet.bytes, packet.length), "invalid TCP option fixture checksum failed");
    checkPassThrough("TCP option length below option header size", line, &packet, true);
    packet                    = options;
    const size_t tcp_options  = IP_HLEN + 4 + TCP_HLEN;
    packet.bytes[tcp_options] = packet.bytes[tcp_options + 1] = packet.bytes[tcp_options + 2] = 1;
    packet.bytes[tcp_options + 3]                                                             = 0xfd;
    require(calcFullPacketChecksum(packet.bytes, packet.length), "truncated TCP option fixture checksum failed");
    checkPassThrough("TCP option length byte missing", line, &packet, true);

    packet = syn;
    packet.bytes[10] ^= 0x01;
    checkPassThrough("bad IPv4 checksum", line, &packet, true);
    packet.repair = true;
    checkPassThrough("bad IPv4 checksum with pending repair", line, &packet, true);
    packet = syn;
    packet.bytes[IP_HLEN + 16] ^= 0x01;
    checkPassThrough("bad TCP checksum", line, &packet, true);
    packet.repair = true;
    checkPassThrough("bad TCP checksum with pending repair", line, &packet, true);
}

static void checkOptionFormats(line_t *line)
{
    static const struct
    {
        const char *name;
        uint8_t     ip_options[4];
        uint8_t     tcp_options[4];
        bool        valid;
    } cases[] = {
        {"TCP MSS of 1460 and padded IPv4 EOL", {0, 0, 0, 0}, {2, 4, 5, 180}, true},
        {"NOP followed by zero-padded EOL in IPv4 and TCP", {1, 0, 0, 0}, {1, 0, 0, 0}, true},
        {"TCP MSS length of three", {0, 0, 0, 0}, {2, 3, 5, 0}, false},
        {"nonzero padding after TCP EOL", {0, 0, 0, 0}, {0, 0, 0, 1}, false},
        {"nonzero padding after IPv4 EOL", {0, 0, 0, 1}, {0, 0, 0, 0}, false},
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        testCaseSet(cases[i].name);
        packet_t packet = makeTcpPacket(kFirstTarget, 7493, TCP_SYN, true, 0);
        memoryCopy(packet.bytes + IP_HLEN, cases[i].ip_options, sizeof(cases[i].ip_options));
        memoryCopy(packet.bytes + IP_HLEN + sizeof(cases[i].ip_options) + TCP_HLEN,
                   cases[i].tcp_options,
                   sizeof(cases[i].tcp_options));
        require(calcFullPacketChecksum(packet.bytes, packet.length), "option fixture checksum failed");
        if (cases[i].valid)
            checkOpeningSyn(line, &packet, kFirstTarget, 7493);
        else
            checkPassThrough(cases[i].name, line, &packet, true);
    }
}

static void checkLifecycle(void)
{
    line_t *line = tunnelchainGetWorkerPacketLine(fixture.chain, 0);
    testCaseSet("lifecycle forwarding in both directions");
    fixture.trace_length = 0;
    tunnelNextUpStreamInit(fixture.prev, line);
    tunnelPrevDownStreamInit(fixture.next, line);
    tunnelNextUpStreamEst(fixture.prev, line);
    tunnelPrevDownStreamEst(fixture.next, line);
    for (unsigned i = 0; i < 2; ++i)
    {
        tunnelNextUpStreamPause(fixture.prev, line);
        tunnelPrevDownStreamPause(fixture.next, line);
    }
    for (unsigned i = 0; i < 2; ++i)
    {
        tunnelNextUpStreamResume(fixture.prev, line);
        tunnelPrevDownStreamResume(fixture.next, line);
    }
    const event_t signals[] = {{kInit, true},
                               {kInit, false},
                               {kEst, true},
                               {kEst, false},
                               {kPause, true},
                               {kPause, false},
                               {kPause, true},
                               {kPause, false},
                               {kResume, true},
                               {kResume, false},
                               {kResume, true},
                               {kResume, false}};
    requireTrace(signals, ARRAY_SIZE(signals));

    testCaseSet("reentrant Finish suppresses both pending replies on the closing worker");
    const packet_t first          = makeTcpPacket(kFirstTarget, 7493, TCP_SYN, false, 0);
    const packet_t second         = makeTcpPacket(kSecondTarget, 7494, TCP_SYN, false, 0);
    const event_t  closed[]       = {{kOriginal, true}, {kOriginal, true}, {kFinish, false}};
    fixture.trace_length          = 0;
    fixture.nested_syn            = &second;
    fixture.finish_during_payload = true;
    sendPacket(line, &first, true);
    requireTrace(closed, ARRAY_SIZE(closed));
    require(lineIsAlive(line) && tunnelchainGetWorkerPacketLine(fixture.chain, 0) == line,
            "Finish retired the worker packet line");

    testCaseSet("Finish leaves the other worker's reply path open");
    testWorkerBindWID(1);
    line_t *other = tunnelchainGetWorkerPacketLine(fixture.chain, 1);
    checkOpeningSyn(other, &second, kSecondTarget, 7494);
    testCaseSet("upstream Finish relays to next on the packet line");
    fixture.trace_length = 0;
    tunnelNextUpStreamFinish(fixture.prev, other);
    const event_t finished[] = {{kFinish, true}};
    requireTrace(finished, ARRAY_SIZE(finished));
    require(lineIsAlive(other), "upstream Finish retired the worker packet line");
}

int main(void)
{
    testCaseSet("SynReply fixture setup");
    initWLibc();
    require(createInternalLogger(NULL, true) != NULL, "logger initialization failed");
    require(globalstateInitializeSecureRandom() && frandGlobalInit(), "random initialization failed");
    checkSumInit();
    setupWorkers();

    checkInvalidSettings();
    checkSourceSetting(NULL, false);
    checkSourceSetting("{}", false);
    checkSourceSetting("{\"reply_source_ip\":\"192.0.2.20\"}", true);

    setupChain(NULL);
    line_t *line = tunnelchainGetWorkerPacketLine(fixture.chain, 0);
    checkOpeningPackets(line);
    checkPassThroughPackets(line);
    checkMalformedPackets(line);
    checkOptionFormats(line);
    checkLifecycle();
    teardownChain();

    teardownWorkers();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    internaloggerDestroy();
    return 0;
}
