#include "devices/capture/capture_linux_steering.h"

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
    uint16_t count;
    int      sockets[kMaximumTestLanes + 1][2];
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

static void openLanes(steering_test_t *test, uint16_t count)
{
    require(count > 0 && count <= kMaximumTestLanes, "test lane count is supported");
    test->count = count;
    for (uint16_t lane = 0; lane <= count; ++lane)
    {
        struct
        {
            char    text[kCaptureLinuxSteeringFilterSize];
            uint8_t guard[16];
        } serialized;
        memset(&serialized, 0xa5, sizeof(serialized));
        if (lane == count)
            captureLinuxBuildOpaqueFilter(serialized.text);
        else
            captureLinuxBuildSteeringFilter(count, lane, serialized.text);
        require(memchr(serialized.text, '\0', sizeof(serialized.text)) != NULL, "serialized program is terminated");
        for (unsigned int i = 0; i < sizeof(serialized.guard); ++i)
            require(serialized.guard[i] == 0xa5, "serialization respects its fixed buffer");

        struct sock_filter instructions[XT_BPF_MAX_NUM_INSTR];
        struct sock_fprog  program = {.filter = instructions};
        parseProgram(serialized.text, &program);
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
            require(selectLane(test, packet, sizeof(packet)) == test->count,
                    "opaque complete packets must bypass every flow lane");
            memset(packet + 20, 0xa5, sizeof(packet) - 20);
            require(selectLane(test, packet, sizeof(packet)) == test->count,
                    "opaque protocol payload never supplies ports");
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
        require(selectLane(test, packet, sizeof(packet)) == test->count,
                "opaque IPv4 options retain random-distribution classification");
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

int main(void)
{
    steering_test_t test;
    const uint16_t  counts[] = {1, 3, 16};
    for (unsigned int i = 0; i < sizeof(counts) / sizeof(counts[0]); ++i)
    {
        openLanes(&test, counts[i]);
        testPortDistributionAndSymmetry(&test);
        testFragmentsAndOpaqueProtocols(&test);
        testHeaderBoundsAndCompatibility(&test);
        closeLanes(&test);
    }

    openLanes(&test, kMaximumTestLanes);
    uint8_t packet[kPacketCapacity];
    makePacket(packet, 6, 20);
    for (unsigned int port = 0; port < 64; ++port)
    {
        put16(packet + 20, (uint16_t) port);
        const uint16_t lane = selectLane(&test, packet, sizeof(packet));
        reverseEndpoints(packet);
        require(selectLane(&test, packet, sizeof(packet)) == lane, "maximum worker count retains symmetric coverage");
        reverseEndpoints(packet);
    }
    closeLanes(&test);
    return 0;
}
