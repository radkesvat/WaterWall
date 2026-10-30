#include "devices/capture/capture_linux_steering.h"
#include "devices/device_flow_hash.h"

#include <errno.h>
#include <linux/filter.h>
#include <linux/netfilter/xt_bpf.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum
{
    kMaximumTestLanes = 254,
    kPacketCapacity   = 96
};

typedef struct steering_test_s
{
    uint16_t                  count;
    device_opaque_flow_mode_t mode;
    int                       sockets[kMaximumTestLanes + 1][2];
} steering_test_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "capture_linux_steering_test: %s (errno=%d)\n", message, errno);
        exit(1);
    }
}

static void parseProgram(const char *text, struct sock_fprog *program)
{
    char         *end;
    unsigned long count = strtoul(text, &end, 10);
    require(count > 0 && count <= XT_BPF_MAX_NUM_INSTR && *end == ',', "serialized program has a valid count");
    program->len = (unsigned short) count;
    for (unsigned int i = 0; i < count; ++i)
    {
        unsigned int code, jt, jf, value;
        int          consumed = 0;
        require(*end == ',', "serialized instructions are comma separated");
        require(sscanf(end + 1, "%u %u %u %u%n", &code, &jt, &jf, &value, &consumed) == 4 && consumed > 0,
                "serialized instruction parses");
        require(code <= UINT16_MAX && jt <= UINT8_MAX && jf <= UINT8_MAX, "serialized fields fit classic BPF");
        program->filter[i] =
            (struct sock_filter) {.code = (uint16_t) code, .jt = (uint8_t) jt, .jf = (uint8_t) jf, .k = value};
        end += 1 + consumed;
    }
    require(*end == '\0', "serialized program contains exactly its declared instructions");
}

static void openLanes(steering_test_t *test, uint16_t count, device_opaque_flow_mode_t mode)
{
    require(count > 0 && count <= kMaximumTestLanes, "test lane count is supported");
    test->count = count;
    test->mode  = mode;
    for (uint16_t lane = 0; lane <= count; ++lane)
    {
        struct
        {
            char    text[kCaptureLinuxSteeringFilterSize];
            uint8_t guard[16];
        } serialized;
        memset(&serialized, 0xa5, sizeof(serialized));
        if (lane == count)
        {
            if (mode == kDeviceOpaqueFlowSpread)
                captureLinuxBuildOpaqueFilter(serialized.text);
            else
                strcpy(serialized.text, "1,6 0 0 0");
        }
        else
            captureLinuxBuildSteeringFilter(count, lane, mode, serialized.text);
        require(memchr(serialized.text, '\0', sizeof(serialized.text)) != NULL, "serialized program is terminated");
        for (unsigned int i = 0; i < sizeof(serialized.guard); ++i)
            require(serialized.guard[i] == 0xa5, "serialization respects its fixed buffer");

        struct sock_filter instructions[XT_BPF_MAX_NUM_INSTR];
        struct sock_fprog  program = {.filter = instructions};
        parseProgram(serialized.text, &program);
        if (lane < count)
            require(program.len == (mode == kDeviceOpaqueFlowPrefix ? 61U : 64U),
                    "complete steering predicate retains its qualified instruction count");
        require(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, test->sockets[lane]) == 0,
                "create local datagram pair");
        /* The kernel executes the actual serialized cBPF. AF_UNIX exposes the
         * supplied bytes directly, so malformed IP fixtures need no privileges.
         * A match returns one byte here; xt_bpf treats that same return as true. */
        require(setsockopt(test->sockets[lane][1], SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) == 0,
                "kernel accepts the generated steering predicate");
    }
}

static void closeLanes(steering_test_t *test)
{
    for (uint16_t lane = 0; lane <= test->count; ++lane)
    {
        require(close(test->sockets[lane][0]) == 0, "close test sender");
        require(close(test->sockets[lane][1]) == 0, "close test receiver");
    }
}

static uint16_t selectLane(const steering_test_t *test, const uint8_t *packet, size_t length)
{
    unsigned int matched  = 0;
    uint16_t     selected = 0;
    for (uint16_t lane = 0; lane <= test->count; ++lane)
    {
        ssize_t sent;
        do
            sent = send(test->sockets[lane][0], packet, length, 0);
        while (sent < 0 && errno == EINTR);
        require(sent == (ssize_t) length, "send packet to native predicate");
        uint8_t received[kPacketCapacity];
        ssize_t read;
        do
            read = recv(test->sockets[lane][1], received, sizeof(received), 0);
        while (read < 0 && errno == EINTR);
        if (read >= 0)
        {
            require(read == (length == 0 ? 0 : 1), "native predicate returns its boolean match length");
            if (length != 0)
                require(received[0] == packet[0], "native predicate preserves packet bytes");
            selected = lane;
            ++matched;
        }
        else
            require(errno == EAGAIN || errno == EWOULDBLOCK, "unmatched lane has no packet");
    }
    require(matched == 1, "every packet selects exactly one flow lane or the opaque random-distribution class");
    uint32_t hash = UINT32_C(0xa5a5a5a5);
    if (deviceReceiveWorkerHash(packet, (uint32_t) length, test->mode, &hash))
        require(selected == hash % test->count, "actual kernel cBPF matches common C worker hash");
    else
        require(hash == UINT32_C(0xa5a5a5a5), "declined receive classification preserves output hash");
    return selected;
}

static void put16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t) (value >> 8);
    bytes[1] = (uint8_t) value;
}

static void put32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t) (value >> 24);
    bytes[1] = (uint8_t) (value >> 16);
    bytes[2] = (uint8_t) (value >> 8);
    bytes[3] = (uint8_t) value;
}

static void makePacket(uint8_t packet[kPacketCapacity], uint8_t protocol, unsigned int header_length)
{
    memset(packet, 0, kPacketCapacity);
    packet[0] = (uint8_t) (0x40 | (header_length / 4));
    packet[9] = protocol;
    put16(packet + 2, kPacketCapacity);
    put32(packet + 12, UINT32_C(0xc0000201));
    put32(packet + 16, UINT32_C(0xc6336402));
    put16(packet + header_length, 12000);
    put16(packet + header_length + 2, 443);
}

static void reverseEndpoints(uint8_t packet[kPacketCapacity])
{
    uint8_t address[4];
    memcpy(address, packet + 12, sizeof(address));
    memcpy(packet + 12, packet + 16, sizeof(address));
    memcpy(packet + 16, address, sizeof(address));
    const unsigned int header = (packet[0] & 15U) * 4;
    uint8_t            port[2];
    memcpy(port, packet + header, sizeof(port));
    memcpy(packet + header, packet + header + 2, sizeof(port));
    memcpy(packet + header + 2, port, sizeof(port));
}

static void requireAllLanes(const bool *seen, unsigned int count, const char *message)
{
    for (unsigned int lane = 0; lane < count; ++lane)
        require(seen[lane], message);
}

static void testPortDistributionAndSymmetry(steering_test_t *test)
{
    const uint8_t protocols[] = {6, 17};
    for (unsigned int protocol = 0; protocol < sizeof(protocols); ++protocol)
    {
        uint8_t packet[kPacketCapacity];
        bool    source_seen[kMaximumTestLanes] = {0};
        bool    dest_seen[kMaximumTestLanes]   = {0};
        bool    equal_seen[kMaximumTestLanes]  = {0};
        makePacket(packet, protocols[protocol], 20);
        for (unsigned int port = 1; port <= 512; ++port)
        {
            put16(packet + 20, (uint16_t) (12000 + port));
            put16(packet + 22, 443);
            const uint16_t source_lane = selectLane(test, packet, sizeof(packet));
            source_seen[source_lane]   = true;
            reverseEndpoints(packet);
            require(selectLane(test, packet, sizeof(packet)) == source_lane, "transport steering is symmetric");
            reverseEndpoints(packet);

            put16(packet + 20, 12000);
            put16(packet + 22, (uint16_t) (20000 + port));
            dest_seen[selectLane(test, packet, sizeof(packet))] = true;

            put16(packet + 20, (uint16_t) (20000 + port));
            equal_seen[selectLane(test, packet, sizeof(packet))] = true;
        }
        requireAllLanes(source_seen, test->count, "source ports spread same-address connections across all lanes");
        requireAllLanes(dest_seen, test->count, "destination ports spread same-address connections across all lanes");
        requireAllLanes(
            equal_seen, test->count, "equal source/destination ports still distribute distinct connections");

        memcpy(packet + 16, packet + 12, 4);
        put16(packet + 20, 12000);
        put16(packet + 22, 443);
        const uint16_t same_address_lane = selectLane(test, packet, sizeof(packet));
        reverseEndpoints(packet);
        require(selectLane(test, packet, sizeof(packet)) == same_address_lane,
                "same-IP endpoints retain symmetry when ports reverse");
    }
}

static uint16_t expectedOpaque(const steering_test_t *test, const uint8_t *packet, size_t length)
{
    uint32_t hash;
    return deviceReceiveWorkerHash(packet, (uint32_t) length, test->mode, &hash) ? (uint16_t) (hash % test->count)
                                                                                 : test->count;
}

static void testFragmentsAndOpaqueProtocols(steering_test_t *test)
{
    uint8_t packet[kPacketCapacity];
    for (unsigned int protocol = 0; protocol <= UINT8_MAX; ++protocol)
    {
        makePacket(packet, (uint8_t) protocol, 20);
        put16(packet + 6, 0x2000);
        const uint16_t fragment_lane = selectLane(test, packet, sizeof(packet));
        const uint16_t fragments[]   = {0x2000, 0x2001, 1, 0x1fff};
        for (unsigned int fragment = 0; fragment < sizeof(fragments) / sizeof(fragments[0]); ++fragment)
        {
            put16(packet + 6, fragments[fragment]);
            put16(packet + 4, (uint16_t) (123 + fragment));
            put16(packet + 20, (uint16_t) (4000 + fragment));
            put16(packet + 22, (uint16_t) (9000 + fragment));
            require(selectLane(test, packet, sizeof(packet)) == fragment_lane,
                    "first, middle, and final fragments ignore identification and transport bytes");
            reverseEndpoints(packet);
            require(selectLane(test, packet, sizeof(packet)) == fragment_lane, "fragment steering is symmetric");
            reverseEndpoints(packet);
        }
        if (protocol != 6 && protocol != 17)
        {
            put16(packet + 6, 0);
            require(selectLane(test, packet, sizeof(packet)) == expectedOpaque(test, packet, sizeof(packet)),
                    "opaque complete packets follow the selected receive policy");
            memset(packet + 20, 0xa5, sizeof(packet) - 20);
            require(selectLane(test, packet, sizeof(packet)) == expectedOpaque(test, packet, sizeof(packet)),
                    "opaque payload follows the selected prefix or peer policy");
        }
    }
    bool seen[kMaximumTestLanes] = {0};
    makePacket(packet, 1, 20);
    put16(packet + 6, 0x2000);
    for (unsigned int address = 0; address < 512; ++address)
    {
        put32(packet + 12, UINT32_C(0xc0000200) + address);
        seen[selectLane(test, packet, sizeof(packet))] = true;
    }
    requireAllLanes(seen, test->count, "address fallback still distributes traffic across all lanes");
}

static void testHeaderBoundsAndCompatibility(steering_test_t *test)
{
    uint8_t packet[kPacketCapacity];
    makePacket(packet, 6, 20);
    const uint16_t ordinary_lane = selectLane(test, packet, sizeof(packet));
    put16(packet + 6, 0x4000);
    require(selectLane(test, packet, sizeof(packet)) == ordinary_lane, "DF does not change transport steering");
    for (unsigned int header = 20; header <= 60; header += 4)
    {
        makePacket(packet, 6, header);
        memset(packet + 20, 0xa5, header - 20);
        require(selectLane(test, packet, sizeof(packet)) == ordinary_lane, "IPv4 options do not change port identity");
        put16(packet + 2, (uint16_t) (header + 4));
        require(selectLane(test, packet, header + 4) == ordinary_lane,
                "exact four-byte TCP prefix remains eligible without parsing a TCP header");
        put16(packet + 6, 0x2000);
        const uint16_t fallback = selectLane(test, packet, sizeof(packet));
        put16(packet + 6, 0);
        for (unsigned int payload = 0; payload < 4; ++payload)
        {
            put16(packet + 2, (uint16_t) (header + payload));
            require(selectLane(test, packet, header + payload) == fallback,
                    "short transport prefixes retain address/protocol steering");
            require(selectLane(test, packet, sizeof(packet)) == fallback,
                    "bytes beyond declared length cannot supply transport ports");
        }
        put16(packet + 2, (uint16_t) (header - 1));
        require(selectLane(test, packet, sizeof(packet)) == 0, "declared length shorter than header selects lane zero");
        put16(packet + 2, (uint16_t) (header + 4));
        require(selectLane(test, packet, header + 3) == 0, "truncated declared packet selects lane zero");
    }

    makePacket(packet, 6, 20);
    for (unsigned int length = 0; length < 20; ++length)
        require(selectLane(test, packet, length) == 0, "short IPv4 input selects lane zero");
    for (unsigned int version = 0; version < 16; ++version)
    {
        if (version == 4)
            continue;
        packet[0] = (uint8_t) ((version << 4) | 5);
        require(selectLane(test, packet, sizeof(packet)) == 0, "unsupported IP version selects lane zero");
    }
    for (unsigned int ihl = 0; ihl < 5; ++ihl)
    {
        packet[0] = (uint8_t) (0x40 | ihl);
        require(selectLane(test, packet, sizeof(packet)) == 0, "invalid IPv4 IHL selects lane zero");
    }
    makePacket(packet, 6, 60);
    require(selectLane(test, packet, 20) == 0, "truncated IPv4 options select lane zero");
    makePacket(packet, 17, 20);
    put16(packet + 2, UINT16_MAX);
    require(selectLane(test, packet, sizeof(packet)) == 0, "oversized declared IPv4 length selects lane zero");

    for (unsigned header = 20; header <= 60; header += 4)
    {
        makePacket(packet, 50, header);
        require(selectLane(test, packet, sizeof(packet)) == expectedOpaque(test, packet, sizeof(packet)),
                "opaque IPv4 options follow the selected receive policy");
        put16(packet + 2, (uint16_t) (header - 1));
        require(selectLane(test, packet, sizeof(packet)) == 0,
                "opaque malformed declared length must reach reader validation exactly once");
        put16(packet + 2, (uint16_t) (header + 8));
        require(selectLane(test, packet, header + 7) == 0,
                "opaque truncated packet must not match the random-distribution class");
    }
    makePacket(packet, 50, 20);
    for (unsigned length = 0; length < 20; ++length)
        require(selectLane(test, packet, length) == 0, "opaque short IPv4 must reach lane-zero validation");
    packet[0] = 0x65;
    require(selectLane(test, packet, sizeof(packet)) == 0, "opaque unsupported IP version must not be classified");
    packet[0] = 0x44;
    require(selectLane(test, packet, sizeof(packet)) == 0, "opaque invalid IHL must not be classified");
}

/* Frozen before candidate execution: all twelve corpora contain 65,536 tuples,
 * hence at least 258 expected entries per worker. Every bucket must remain
 * between one half and three halves of its expectation, for counts 3,7,16,254.
 * The original seven corpora are followed by the old public port-443 collapse,
 * equal/complementary/high-bit endpoint words, and a zero endpoint word.
 * device_flow_affinity_test separately retains its existing 4,096 correlated
 * address/port corpus and its unchanged four-worker balance thresholds.
 * These are finite placement checks, not a throughput benchmark. */
static void qualifyWorkerHash(void)
{
    /* The old endpoint product maps this public IPv4 server on port 443 to
     * zero: 0xC9FF954B == 443 * 0x9E3779B1 modulo 2^32. Its other endpoint
     * must still distinguish client flows instead of collapsing every port. */
    require(deviceFlowWorkerHashTuple(0x0a000001, 10000, 0xc9ff954b, 443, 6, 0) !=
                deviceFlowWorkerHashTuple(0x0a000001, 10001, 0xc9ff954b, 443, 6, 0),
            "a public port-443 server must not erase the client endpoint");
    const struct
    {
        uint32_t src;
        uint16_t sp;
        uint32_t dst;
        uint16_t dp;
        uint8_t  proto;
        uint32_t expected;
    } vectors[] = {
        {0x0a000001, 40000, 0x0a000002, 443, 6, 0xc4d8d18a},
        {0x0a000101, 40000, 0x0a000102, 443, 6, 0x2dd3fcf0},
        {0x0a000001, 10000, 0x0a000002, 46539, 6, 0x79464f88},
        {0x0a000001, 42768, 0x0a000002, 46539, 6, 0xad16e4d0},
        {0xc0000201, 12000, 0xc6336402, 443, 17, 0x0af11122},
        {0xc0000201, 0, 0xc6336402, 0, 1, 0xab7cc5f9},
        {0xc0000201, 12000, 0xc6336402, 443, 132, 0xad52e624},
        {0x0a000001, 443, 0x0a000001, 443, 6, 0x7150af28},
        {0x0a000001, 10000, 0xc9ff954b, 443, 6, 0xbdb9365e},
        {0x0a000001, 10001, 0xc9ff954b, 443, 6, 0x89e8530b},
        {0x0a000001, 10000, 0x000001bb, 443, 6, 0xb6878f90},
        {0x0a000001, 10001, 0x000001bb, 443, 6, 0x82b60aa5},
    };
    for (unsigned i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i)
    {
        require(deviceFlowWorkerHashTuple(
                    vectors[i].src, vectors[i].sp, vectors[i].dst, vectors[i].dp, vectors[i].proto, 0) ==
                    vectors[i].expected,
                "worker hash matches an independently calculated fixed H32 vector");
        require(deviceFlowWorkerHashTuple(
                    vectors[i].dst, vectors[i].dp, vectors[i].src, vectors[i].sp, vectors[i].proto, 0) ==
                    vectors[i].expected,
                "fixed H32 vector is symmetric even for equal endpoint fields");
    }
    const uint16_t counts[]       = {3, 7, 16, 254};
    const uint16_t destinations[] = {53, 80, 443, 46539};
    for (unsigned corpus = 0; corpus < 12; ++corpus)
        for (unsigned ci = 0; ci < sizeof(counts) / sizeof(counts[0]); ++ci)
        {
            uint32_t buckets[kMaximumTestLanes] = {0};
            for (uint32_t i = 0; i < 65536; ++i)
            {
                uint32_t src = UINT32_C(0x0a000001), dst = UINT32_C(0x0a000002);
                uint16_t sp = (uint16_t) i, dp = 443;
                uint8_t  proto = 6;
                if (corpus >= 1 && corpus <= 4)
                {
                    sp = (uint16_t) (i * 257U);
                    dp = destinations[corpus - 1];
                }
                else if (corpus == 5)
                {
                    src = UINT32_C(0x0a000000) + i;
                    dst = src ^ UINT32_C(0x01010101);
                    sp  = 40000;
                }
                else if (corpus == 6)
                {
                    sp    = (uint16_t) (i * 251U);
                    dp    = (uint16_t) (i * 509U + 71U);
                    proto = 132;
                }
                else if (corpus == 7)
                    dst = UINT32_C(0xc9ff954b);
                else if (corpus >= 8)
                {
                    /* With zero ports the tuple API accepts the exact
                     * encoded values used by the arithmetic qualification. */
                    src = corpus == 10 ? i << 16U : i;
                    dst = corpus == 8 ? i : corpus == 9 ? ~i : 0;
                    sp = dp = 0;
                }
                ++buckets[deviceFlowWorkerHashTuple(src, sp, dst, dp, proto, 0) % counts[ci]];
            }
            for (unsigned lane = 0; lane < counts[ci]; ++lane)
                require(buckets[lane] * counts[ci] >= 32768U && buckets[lane] * counts[ci] <= 98304U,
                        "frozen structured corpus stays within 50%-150% per-bucket distribution bounds");
        }
    const uint32_t a = deviceFlowWorkerHashTuple(0x0a000001, 40000, 0x0a000002, 443, 6, 0);
    require(a != deviceFlowWorkerHashTuple(0x0a000101, 40000, 0x0a000102, 443, 6, 0),
            "same address XOR does not force the old RawSocket structural collision");
    require(deviceFlowWorkerHashTuple(0x0a000001, 10000, 0x0a000002, 46539, 6, 0) !=
                deviceFlowWorkerHashTuple(0x0a000001, 42768, 0x0a000002, 46539, 6, 0),
            "ports separated by 32768 avoid the old fixed-destination structural collision");
    require(a != deviceFlowWorkerHashTuple(0x0a000001, 443, 0x0a000002, 40000, 6, 0),
            "ports retain their endpoint address association");
}

static void testFixedZeroEndpointVectors(const steering_test_t *test)
{
    static const struct
    {
        uint32_t destination, hash;
        uint16_t source_port;
    } vectors[] = {{UINT32_C(0xc9ff954b), UINT32_C(0xbdb9365e), 10000},
                   {UINT32_C(0xc9ff954b), UINT32_C(0x89e8530b), 10001},
                   {UINT32_C(0x000001bb), UINT32_C(0xb6878f90), 10000},
                   {UINT32_C(0x000001bb), UINT32_C(0x82b60aa5), 10001}};
    for (unsigned i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i)
    {
        uint8_t packet[kPacketCapacity];
        makePacket(packet, 6, 20);
        put32(packet + 12, UINT32_C(0x0a000001));
        put32(packet + 16, vectors[i].destination);
        put16(packet + 20, vectors[i].source_port);
        put16(packet + 22, 443);
        require(selectLane(test, packet, sizeof(packet)) == vectors[i].hash % test->count,
                "actual cBPF matches fixed zero-endpoint and endpoint-encoding vectors");
        reverseEndpoints(packet);
        require(selectLane(test, packet, sizeof(packet)) == vectors[i].hash % test->count,
                "actual cBPF zero-endpoint vectors retain reverse symmetry");
    }
}

static void testOpaqueModeKeys(steering_test_t *test)
{
    uint8_t  storage[kPacketCapacity + 1];
    uint8_t *packet = storage + 1; /* Explicitly unaligned packet bytes. */
    for (unsigned header = 20; header <= 60; header += 4)
    {
        makePacket(packet, 132, header);
        const uint16_t lane = selectLane(test, packet, kPacketCapacity);
        uint32_t       prefix_hash;
        const bool     deterministic = deviceReceiveWorkerHash(packet, kPacketCapacity, test->mode, &prefix_hash);
        for (unsigned byte = header + 4; byte < kPacketCapacity; ++byte)
        {
            packet[byte] ^= 0xa5;
            require(selectLane(test, packet, kPacketCapacity) == lane,
                    "later opaque payload bytes do not alter receive classification");
        }
        if (test->mode == kDeviceOpaqueFlowPeer)
        {
            for (unsigned byte = header; byte < kPacketCapacity; ++byte)
            {
                packet[byte] ^= 0x5a;
                require(selectLane(test, packet, kPacketCapacity) == lane, "peer ignores every payload byte");
            }
        }
        if (deterministic)
        {
            uint32_t unaligned_hash;
            require(deviceReceiveWorkerHash(packet, kPacketCapacity, test->mode, &unaligned_hash),
                    "unaligned input is supported");
            require(unaligned_hash == prefix_hash, "fixed masks after the prefix retain stable opaque identity");
        }
        for (unsigned payload = 0; payload <= 4; ++payload)
        {
            put16(packet + 2, (uint16_t) (header + payload));
            require(selectLane(test, packet, header + payload) == expectedOpaque(test, packet, header + payload),
                    "opaque zero-through-four-byte payload follows selected fallback policy");
            require(selectLane(test, packet, kPacketCapacity) == expectedOpaque(test, packet, header + payload),
                    "trailing buffer bytes never supply an opaque prefix");
        }
    }
}

static void testWorkerHashApiBoundaries(void)
{
    uint8_t  storage[49] = {0};
    uint8_t *packet      = storage + 1;
    packet[0]            = 0x60;
    packet[6]            = 6;
    put16(packet + 4, 4);
    const uint32_t source[]      = {0x20010db8, 0x00010002, 0x00030004, 0x00050006};
    const uint32_t destination[] = {0x20010db8, 0x00070008, 0x0009000a, 0x000b000c};
    for (unsigned word = 0; word < 4; ++word)
    {
        put32(packet + 8 + word * 4, source[word]);
        put32(packet + 24 + word * 4, destination[word]);
    }
    put16(packet + 40, 23456);
    put16(packet + 42, 443);
    uint32_t hash = 0;
    require(deviceFlowWorkerHash(packet, 44, &hash) && hash == UINT32_C(0x23f6d8c9),
            "unaligned generic IPv6 worker hash retains existing address folding");
    for (device_opaque_flow_mode_t mode = kDeviceOpaqueFlowPrefix; mode <= kDeviceOpaqueFlowSpread; ++mode)
    {
        require(deviceReceiveWorkerHash(packet, 44, mode, &hash) && hash == UINT32_C(0x23f6d8c9),
                "all receive modes share plain IPv6 native worker hash");
        require(! deviceReceiveWorkerHash(packet, 48, mode, &hash), "IPv6 receive rejects trailing buffer bytes");
        packet[6] = 0;
        require(! deviceReceiveWorkerHash(packet, 44, mode, &hash), "IPv6 receive does not walk extension headers");
        packet[6] = 6;
        put16(packet + 4, 3);
        require(! deviceReceiveWorkerHash(packet, 43, mode, &hash), "IPv6 receive retains four-byte native boundary");
        put16(packet + 4, 4);
        require(! deviceReceiveWorkerHash(NULL, 44, mode, &hash) && ! deviceReceiveWorkerHash(packet, 0, mode, &hash) &&
                    ! deviceReceiveWorkerHash(packet, 44, mode, NULL),
                "receive hash handles valid null and zero-length input");
    }
    hash = UINT32_C(0xa5a5a5a5);
    require(! deviceFlowWorkerHash(NULL, 44, &hash) && ! deviceFlowWorkerHash(packet, 0, &hash) &&
                ! deviceFlowWorkerHash(packet, 44, NULL),
            "generic worker hash handles null and zero-length input");
    require(hash == UINT32_C(0xa5a5a5a5), "generic hash refusal leaves the output untouched");
    put16(packet + 4, 0);
    require(! deviceFlowWorkerHash(packet, 44, &hash), "generic worker hash rejects IPv6 jumbogram marker");
    put16(packet + 4, 9);
    require(! deviceFlowWorkerHash(packet, 44, &hash), "generic worker hash rejects truncated declared IPv6 length");
}

int main(void)
{
    qualifyWorkerHash();
    testWorkerHashApiBoundaries();
    steering_test_t test;
    const uint16_t  counts[] = {1, 3, 7, 16};
    for (device_opaque_flow_mode_t mode = kDeviceOpaqueFlowPrefix; mode <= kDeviceOpaqueFlowSpread; ++mode)
        for (unsigned int i = 0; i < sizeof(counts) / sizeof(counts[0]); ++i)
        {
            openLanes(&test, counts[i], mode);
            testFixedZeroEndpointVectors(&test);
            testPortDistributionAndSymmetry(&test);
            testFragmentsAndOpaqueProtocols(&test);
            testHeaderBoundsAndCompatibility(&test);
            testOpaqueModeKeys(&test);
            closeLanes(&test);
        }

    for (device_opaque_flow_mode_t mode = kDeviceOpaqueFlowPrefix; mode <= kDeviceOpaqueFlowSpread; ++mode)
    {
        openLanes(&test, kMaximumTestLanes, mode);
        testFixedZeroEndpointVectors(&test);
        uint8_t packet[kPacketCapacity];
        makePacket(packet, 6, 20);
        for (unsigned int port = 0; port < 64; ++port)
        {
            put16(packet + 20, (uint16_t) port);
            const uint16_t lane = selectLane(&test, packet, sizeof(packet));
            reverseEndpoints(packet);
            require(selectLane(&test, packet, sizeof(packet)) == lane,
                    "maximum worker count retains symmetric coverage");
            reverseEndpoints(packet);
        }
        closeLanes(&test);
    }
    return 0;
}
