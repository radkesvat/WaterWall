/* Startup rollback and real-kernel common32, prefix/peer/spread steering invariants.
 * CTest: waterwall.tun_linux_queues_unit, waterwall.tun_linux_steering_kernel */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "devices/device_flow_hash.h"
#include "devices/tun/tun_linux_queues.h"
#include "test_assert.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

enum
{
    kFirstFd         = 700,
    kProgramFd       = 900,
    kMapFd           = 901,
    kQueueFdBase     = 1000,
    kRequestedQueues = 7
};

static device_opaque_flow_mode_t opaque_mode;
static uint16_t                  queue_count;
static bool                      multiqueue;
static bool                      checksum;
static bool                      run_kernel;
static int                       kernel_fd = -1;
static int                       get_error;
static int                       map_error;
static int                       load_error;
static int                       steering_error;
static unsigned                  open_fail_at;
static unsigned                  attach_fail_at;
static unsigned                  open_calls;
static unsigned                  attach_calls;
static unsigned                  map_calls;
static unsigned                  load_calls;
static unsigned                  steering_calls;
static unsigned                  close_calls;
static int                       closed[16];

int  __wrap_open(const char *path, int flags, ...);
int  __wrap_ioctl(int fd, unsigned long request, ...);
int  __wrap_close(int fd);
long __wrap_syscall(long number, ...);
long __real_syscall(long number, ...);
int  __real_close(int fd);

static void reset(void)
{
    opaque_mode    = kDeviceOpaqueFlowSpread;
    multiqueue     = true;
    checksum       = false;
    get_error      = 0;
    map_error      = 0;
    load_error     = 0;
    steering_error = 0;
    open_fail_at   = 0;
    attach_fail_at = 0;
    open_calls     = 0;
    attach_calls   = 0;
    map_calls      = 0;
    load_calls     = 0;
    steering_calls = 0;
    close_calls    = 0;
    memset(closed, 0, sizeof(closed));
}

int __wrap_open(const char *path, int flags, ...)
{
    require(strcmp(path, "/dev/net/tun") == 0, "only opens the TUN clone device");
    require(flags == (O_RDWR | O_NONBLOCK | O_CLOEXEC), "extra queues are nonblocking and close-on-exec");
    ++open_calls;
    if (open_calls == open_fail_at)
    {
        errno = EMFILE;
        return -1;
    }
    return kQueueFdBase + (int) open_calls;
}

int __wrap_ioctl(int fd, unsigned long request, ...)
{
    va_list args;
    va_start(args, request);
    void *argument = va_arg(args, void *);
    va_end(args);
    if (request == TUNGETIFF)
    {
        require(fd == kFirstFd, "queries the original queue");
        if (get_error != 0)
        {
            errno = get_error;
            return -1;
        }
        ((struct ifreq *) argument)->ifr_flags = IFF_TUN | IFF_NO_PI | (multiqueue ? IFF_MULTI_QUEUE : 0);
        return 0;
    }
    if (request == TUNSETSTEERINGEBPF)
    {
        require(fd == kFirstFd, "steering belongs to the original interface");
        require(open_calls == 0, "stable steering precedes extra-queue publication");
        ++steering_calls;
        if (steering_error != 0)
        {
            errno = steering_error;
            return -1;
        }
        if (run_kernel)
        {
            kernel_fd = dup(*(int *) argument);
            require(kernel_fd >= 0, "retains the actual kernel program for packet testing");
        }
        else
        {
            require(*(int *) argument == kProgramFd, "installs the loaded steering program");
        }
        return 0;
    }
    require(request == TUNSETIFF, "only expected TUN ioctls are used");
    require(fd == kQueueFdBase + (int) open_calls, "attaches the newly opened descriptor");
    require(steering_calls == 1, "no multiqueue attachment without stable steering");
    const struct ifreq *ifr = argument;
    require(strcmp(ifr->ifr_name, "wwqueues") == 0, "all queues attach to the original interface name");
    require(ifr->ifr_flags == (IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE | (checksum ? IFF_VNET_HDR : 0)),
            "all queues preserve framing flags without exclusive-create");
    ++attach_calls;
    if (attach_calls == attach_fail_at)
    {
        errno = EBUSY;
        return -1;
    }
    return 0;
}

int __wrap_close(int fd)
{
    require(fd != kFirstFd, "the first descriptor remains caller-owned");
    require(close_calls < sizeof(closed) / sizeof(closed[0]), "bounded descriptor cleanup");
    closed[close_calls++] = fd;
    if (run_kernel && fd < kFirstFd)
    {
        return __real_close(fd);
    }
    errno = EBADF; /* Cleanup must preserve the reason for selecting fallback. */
    return 0;
}

long __wrap_syscall(long number, ...)
{
    require(number == SYS_bpf, "only the bpf syscall is used");
    va_list args;
    va_start(args, number);
    const int       command = va_arg(args, int);
    union bpf_attr *attr    = va_arg(args, union bpf_attr *);
    const size_t    size    = va_arg(args, size_t);
    va_end(args);
    if (command == BPF_MAP_CREATE)
    {
        require(attr->map_type == BPF_MAP_TYPE_PERCPU_ARRAY && attr->key_size == sizeof(uint32_t) &&
                    attr->value_size == sizeof(uint32_t) && attr->max_entries == 1,
                "each interface has one zero-initialized bounded cursor per CPU");
        ++map_calls;
        if (map_error != 0)
        {
            errno = map_error;
            return -1;
        }
        return run_kernel ? __real_syscall(number, command, attr, size) : kMapFd;
    }
    require(command == BPF_PROG_LOAD && map_calls == (opaque_mode == kDeviceOpaqueFlowSpread ? 1U : 0U),
            "only spread steering creates a counter before loading its program");
    const struct bpf_insn *program        = (const struct bpf_insn *) (uintptr_t) attr->insns;
    unsigned               map_references = 0;
    for (uint32_t i = 0; i < attr->insn_cnt; ++i)
        if (program[i].code == (BPF_LD | BPF_DW | BPF_IMM) && program[i].src_reg == BPF_PSEUDO_MAP_FD)
            ++map_references;
    require(map_references == (opaque_mode == kDeviceOpaqueFlowSpread ? 1U : 0U),
            "deterministic steering never refers to an opaque cursor map");
    require(attr->prog_type == BPF_PROG_TYPE_SOCKET_FILTER, "TUN steering accepts socket-filter programs");
    require(attr->insn_cnt > 0 && attr->insn_cnt <= 192, "steering is a bounded fixed program");
    ++load_calls;
    if (load_error != 0)
    {
        errno = load_error;
        return -1;
    }
    if (run_kernel)
    {
        char verifier_log[16384] = {0};
        attr->log_buf            = (uint64_t) (uintptr_t) verifier_log;
        attr->log_size           = sizeof(verifier_log);
        attr->log_level          = 1;
        const long result        = __real_syscall(number, command, attr, size);
        if (result < 0 && errno != EPERM && errno != EACCES && errno != ENOSYS)
        {
            fprintf(stderr, "BPF verifier: %s\n", verifier_log);
        }
        return result;
    }
    return kProgramFd;
}

static uint16_t openQueues(uint16_t count, int *fds, const char **reason)
{
    queue_count = count;
    return tunLinuxQueuesOpen(kFirstFd, "wwqueues", checksum, count, fds, reason, opaque_mode);
}

static void testSetup(void)
{
    int         fds[kRequestedQueues];
    const char *reason;

    reset();
    require(openQueues(1, fds, &reason) == 1 && fds[0] == kFirstFd && reason == NULL,
            "one-worker mode needs no optional kernel facility");
    require(map_calls == 0 && load_calls == 0 && open_calls == 0, "one-worker setup performs no optional work");

    reset();
    multiqueue = false;
    require(openQueues(kRequestedQueues, fds, &reason) == 1 && reason != NULL && errno == EOPNOTSUPP,
            "legacy single-queue interfaces retain one reader");
    require(map_calls == 0 && load_calls == 0 && open_calls == 0, "legacy mode never changes steering");

    reset();
    get_error = ENOTTY;
    require(openQueues(kRequestedQueues, fds, &reason) == 1 && reason != NULL && errno == ENOTTY,
            "flag query failure retains the original descriptor");

    reset();
    map_error = EPERM;
    require(openQueues(kRequestedQueues, fds, &reason) == 1 && reason != NULL && errno == EPERM,
            "denied counter-map creation selects single-worker fallback");
    require(map_calls == 1 && load_calls == 0 && steering_calls == 0 && open_calls == 0 && close_calls == 0,
            "failed map creation leaves no program or extra descriptors");

    reset();
    load_error = EPERM;
    require(openQueues(kRequestedQueues, fds, &reason) == 1 && reason != NULL && errno == EPERM,
            "denied BPF permission selects single-worker fallback");
    require(steering_calls == 0 && open_calls == 0 && close_calls == 1 && closed[0] == kMapFd,
            "failed program load releases its counter map and preserves the load error");

    reset();
    load_error = EINVAL;
    require(openQueues(kRequestedQueues, fds, &reason) == 1 && reason != NULL && errno == EINVAL,
            "refused per-CPU steering program selects single-worker fallback");
    require(close_calls == 1 && closed[0] == kMapFd && steering_calls == 0 && open_calls == 0,
            "verifier refusal releases the counter without publishing any extra queues");

    reset();
    steering_error = EINVAL;
    require(openQueues(kRequestedQueues, fds, &reason) == 1 && reason != NULL && errno == EINVAL,
            "unsupported steering hook selects fallback");
    require(close_calls == 2 && closed[0] == kMapFd && closed[1] == kProgramFd && open_calls == 0,
            "failed attach releases both BPF descriptors");

    reset();
    open_fail_at = 3;
    require(openQueues(kRequestedQueues, fds, &reason) == 1 && reason != NULL && errno == EMFILE,
            "partial queue opening rolls back to one");
    require(close_calls == 4 && closed[0] == kMapFd && closed[1] == kProgramFd && closed[2] == kQueueFdBase + 2 &&
                closed[3] == kQueueFdBase + 1,
            "rollback releases extra queues in reverse order");
    for (unsigned i = 1; i < kRequestedQueues; ++i)
    {
        require(fds[i] == -1, "rolled-back and unopened outputs are invalidated");
    }

    reset();
    attach_fail_at = 2;
    require(openQueues(kRequestedQueues, fds, &reason) == 1 && reason != NULL && errno == EBUSY,
            "partial attachment failure preserves the real error");
    require(close_calls == 4 && closed[0] == kMapFd && closed[1] == kProgramFd && closed[2] == kQueueFdBase + 2 &&
                closed[3] == kQueueFdBase + 1,
            "attachment failure closes both current and prior extras");

    for (unsigned offload = 0; offload < 2; ++offload)
    {
        reset();
        checksum = offload != 0;
        require(openQueues(kRequestedQueues, fds, &reason) == kRequestedQueues && reason == NULL,
                "all queues publish only after complete setup");
        require(open_calls == kRequestedQueues - 1 && attach_calls == open_calls && map_calls == 1 && load_calls == 1 &&
                    close_calls == 2 && closed[0] == kMapFd && closed[1] == kProgramFd,
                "successful setup transfers every queue and releases the map and program descriptors");
        for (unsigned i = 1; i < kRequestedQueues; ++i)
        {
            require(fds[i] == kQueueFdBase + (int) i, "queue-index order matches descriptor order");
        }
    }
    const device_opaque_flow_mode_t deterministic_modes[] = {kDeviceOpaqueFlowPrefix, kDeviceOpaqueFlowPeer};
    for (unsigned i = 0; i < sizeof(deterministic_modes) / sizeof(deterministic_modes[0]); ++i)
    {
        reset();
        opaque_mode = deterministic_modes[i];
        map_error   = EPERM;
        require(openQueues(kRequestedQueues, fds, &reason) == kRequestedQueues && reason == NULL,
                "deterministic mode does not require counter-map privileges");
        require(map_calls == 0 && load_calls == 1 && close_calls == 1 && closed[0] == kProgramFd,
                "prefix and peer load no spreading resources");
    }
}

static uint32_t runPacket(const uint8_t *packet, uint32_t length)
{
    /* BPF_PROG_TEST_RUN removes its Ethernet header before a socket-filter
     * program runs. TUN supplies the IP payload at that same skb offset. */
    uint8_t frame[14 + 80] = {0};
    require(length <= sizeof(frame) - 14, "packet fixture fits in its Ethernet wrapper");
    frame[12] = 0x08;
    if (length < 20)
    {
        /* An IPv4 Ethernet type makes the test-run skb builder reject a short
         * IP header before this production filter can inspect it. */
        frame[12] = 0x88;
        frame[13] = 0xB5;
    }
    memcpy(frame + 14, packet, length);
    union bpf_attr attr    = {0};
    attr.test.prog_fd      = (uint32_t) kernel_fd;
    attr.test.data_in      = (uint64_t) (uintptr_t) frame;
    attr.test.data_size_in = 14 + length;
    attr.test.repeat       = 1;
    const long result      = __real_syscall(SYS_bpf, BPF_PROG_TEST_RUN, &attr, sizeof(attr));
    if (result != 0)
    {
        fprintf(stderr, "BPF packet test failed for %u IP bytes: %s\n", length, strerror(errno));
    }
    require(result == 0, "kernel executes the installed production steering program");
    require(attr.test.retval < queue_count, "all packets select an attached queue");
    return attr.test.retval;
}

static void put16(uint8_t *field, uint16_t value)
{
    field[0] = (uint8_t) (value >> 8);
    field[1] = (uint8_t) value;
}

static void makePacket(uint8_t *packet, uint32_t length, uint8_t protocol)
{
    memset(packet, 0, length);
    packet[0]  = 0x45;
    packet[6]  = 0x40;
    packet[8]  = 64;
    packet[9]  = protocol;
    packet[12] = 10;
    packet[15] = 1;
    packet[16] = 192;
    packet[18] = 2;
    packet[19] = 42;
    put16(packet + 2, (uint16_t) length);
    put16(packet + 20, 12345);
    put16(packet + 22, 443);
}

static void reverseEndpoints(uint8_t *packet, unsigned header_length)
{
    uint8_t endpoint[4];
    memcpy(endpoint, packet + 12, 4);
    memcpy(packet + 12, packet + 16, 4);
    memcpy(packet + 16, endpoint, 4);
    memcpy(endpoint, packet + header_length, 2);
    memcpy(packet + header_length, packet + header_length + 2, 2);
    memcpy(packet + header_length + 2, endpoint, 2);
}

static uint32_t addressQueue(const uint8_t *packet)
{
    const uint32_t src =
        ((uint32_t) packet[12] << 24) | ((uint32_t) packet[13] << 16) | ((uint32_t) packet[14] << 8) | packet[15];
    const uint32_t dst =
        ((uint32_t) packet[16] << 24) | ((uint32_t) packet[17] << 16) | ((uint32_t) packet[18] << 8) | packet[19];
    return deviceFlowWorkerHashTuple(src, 0, dst, 0, packet[9], 0) % queue_count;
}

static void requireAllQueues(const bool *observed, const char *message)
{
    for (unsigned i = 0; i < kRequestedQueues; ++i)
    {
        require(observed[i], message);
    }
}

static uint32_t processingQueue(const uint8_t *packet, uint32_t length)
{
    uint32_t hash;
    require(deviceFlowWorkerHash(packet, length, &hash), "transport fixture has a valid processing-worker hash");
    return hash % queue_count;
}

static void testTransportSteering(void)
{
    const uint8_t protocols[] = {6, 17};
    for (unsigned p = 0; p < sizeof(protocols); ++p)
    {
        uint8_t packet[80];
        makePacket(packet, sizeof(packet), protocols[p]);
        bool source_queues[kRequestedQueues]      = {0};
        bool destination_queues[kRequestedQueues] = {0};
        for (unsigned port = 1; port <= 256; ++port)
        {
            put16(packet + 20, (uint16_t) (10000 + port));
            put16(packet + 22, 443);
            const uint32_t source_queue = runPacket(packet, sizeof(packet));
            source_queues[source_queue] = true;
            require(source_queue == processingQueue(packet, sizeof(packet)),
                    "native transport steering matches processing-worker affinity");
            reverseEndpoints(packet, 20);
            require(runPacket(packet, sizeof(packet)) == source_queue,
                    "reversing both addresses and ports preserves a transport queue");
            reverseEndpoints(packet, 20);

            put16(packet + 20, 12345);
            put16(packet + 22, (uint16_t) (20000 + port));
            const uint32_t destination_queue      = runPacket(packet, sizeof(packet));
            destination_queues[destination_queue] = true;
            require(destination_queue == processingQueue(packet, sizeof(packet)),
                    "destination port contributes to the shared processing-worker affinity");
        }
        requireAllQueues(source_queues, "source ports distribute same-address transport connections across queues");
        requireAllQueues(destination_queues,
                         "destination ports distribute same-address transport connections across queues");

        /* Same-address endpoints still associate their corresponding words. */
        memcpy(packet + 16, packet + 12, 4);
        const uint32_t same_address_queue = runPacket(packet, sizeof(packet));
        require(same_address_queue == processingQueue(packet, sizeof(packet)),
                "same-address endpoint ordering matches processing-worker affinity");
        reverseEndpoints(packet, 20);
        require(runPacket(packet, sizeof(packet)) == same_address_queue,
                "same-address endpoints remain symmetric when only the ports reverse");
    }
}

static void testFragmentFallback(void)
{
    const uint8_t protocols[]                = {6, 17, 1, 132};
    bool          observed[kRequestedQueues] = {0};
    for (unsigned p = 0; p < sizeof(protocols); ++p)
    {
        uint8_t packet[80];
        makePacket(packet, sizeof(packet), protocols[p]);
        for (unsigned address = 1; address <= 128; ++address)
        {
            packet[19]           = (uint8_t) address;
            const uint32_t queue = addressQueue(packet);
            observed[queue]      = true;
            for (unsigned kind = 0; kind < 3; ++kind)
            {
                /* First, middle and final fragments must share one fallback. */
                put16(packet + 6, (uint16_t) (kind == 0 ? 0x2000 : kind == 1 ? 0x2008 : 8));
                put16(packet + 4, (uint16_t) (1000 + address + kind));
                put16(packet + 20, (uint16_t) (30000 + address + kind));
                put16(packet + 22, (uint16_t) (40000 + address + kind));
                require(runPacket(packet, sizeof(packet)) == queue,
                        "all fragments use address/protocol fallback regardless of ports or identification");
                reverseEndpoints(packet, 20);
                require(runPacket(packet, sizeof(packet)) == queue,
                        "fragment fallback is symmetric in the address pair");
                reverseEndpoints(packet, 20);
            }
        }
    }
    requireAllQueues(observed, "fallback endpoint pairs still distribute across all queues");
}

static void testHeaderBounds(void)
{
    uint8_t packet[80];
    makePacket(packet, sizeof(packet), 6);
    const uint32_t ordinary_queue = runPacket(packet, sizeof(packet));
    packet[6]                     = 0;
    require(runPacket(packet, sizeof(packet)) == ordinary_queue, "DF does not change an unfragmented transport queue");
    memmove(packet + 24, packet + 20, sizeof(packet) - 24);
    memset(packet + 20, 0xAB, 4);
    packet[0] = 0x46;
    require(runPacket(packet, sizeof(packet)) == ordinary_queue, "IPv4 options move the transport port offset");
    packet[20]++;
    packet[23]++;
    require(runPacket(packet, sizeof(packet)) == ordinary_queue, "IPv4 option bytes do not contribute ports");
    reverseEndpoints(packet, 24);
    require(runPacket(packet, sizeof(packet)) == ordinary_queue, "IPv4 options preserve endpoint symmetry");

    makePacket(packet, sizeof(packet), 6);
    memmove(packet + 60, packet + 20, 4);
    memset(packet + 20, 0xCD, 40);
    packet[0] = 0x4F;
    put16(packet + 2, 64);
    require(runPacket(packet, sizeof(packet)) == ordinary_queue, "maximum IPv4 IHL locates ports within declared data");

    makePacket(packet, sizeof(packet), 6);
    for (unsigned length = 0; length < 20; ++length)
    {
        require(runPacket(packet, length) == 0, "truncated IPv4 headers select queue zero");
    }
    packet[0] = 0x44;
    require(runPacket(packet, sizeof(packet)) == 0, "an IPv4 IHL shorter than the base header is invalid");
    packet[0] = 0x4F;
    put16(packet + 2, 59);
    require(runPacket(packet, 59) == 0, "truncated IPv4 options are invalid");
    put16(packet + 2, 60);
    require(runPacket(packet, 59) == 0, "declared IPv4 data cannot exceed available bytes");
    packet[0] = 0x46;
    put16(packet + 2, 23);
    require(runPacket(packet, sizeof(packet)) == 0, "declared total length cannot end inside IPv4 options");
    packet[0] = 0x45;
    put16(packet + 2, sizeof(packet) + 1);
    require(runPacket(packet, sizeof(packet)) == 0, "a truncated declared datagram selects queue zero");
    put16(packet + 2, 19);
    require(runPacket(packet, sizeof(packet)) == 0, "total length cannot be shorter than the base header");

    const uint8_t protocols[] = {6, 17};
    for (unsigned p = 0; p < sizeof(protocols); ++p)
    {
        makePacket(packet, sizeof(packet), protocols[p]);
        for (unsigned payload_length = 0; payload_length < 4; ++payload_length)
        {
            put16(packet + 2, (uint16_t) (20 + payload_length));
            require(runPacket(packet, sizeof(packet)) == addressQueue(packet),
                    "trailing bytes outside declared transport payload never contribute ports");
            require(runPacket(packet, 20 + payload_length) == addressQueue(packet),
                    "valid short transport payload uses the address/protocol fallback");
        }
    }

    packet[0] = 0x60;
    require(runPacket(packet, sizeof(packet)) == 0, "unsupported IPv6 retains the single designated reader");
    packet[0] = 0x30;
    require(runPacket(packet, sizeof(packet)) == 0, "unknown IP versions retain the single designated reader");
}

static void testOpaqueDeterministic(void)
{
    const uint8_t protocols[]                = {0, 1, 50, 132, 253, 255};
    bool          observed[kRequestedQueues] = {0};
    for (unsigned p = 0; p < sizeof(protocols); ++p)
    {
        uint8_t packet[80];
        makePacket(packet, sizeof(packet), protocols[p]);
        uint32_t hash = 0;
        require(deviceReceiveWorkerHash(packet, sizeof(packet), opaque_mode, &hash),
                "deterministic opaque packet has a software receive key");
        const uint32_t stable_queue = hash % queue_count;
        require(runPacket(packet, sizeof(packet)) == stable_queue,
                "opaque kernel steering agrees with the effective software mode");
        for (unsigned repeat = 0; repeat < 256; ++repeat)
        {
            packet[4]  = (uint8_t) repeat;
            packet[10] = (uint8_t) (repeat * 7);
            memset(packet + 24, (int) repeat, sizeof(packet) - 24);
            if (opaque_mode == kDeviceOpaqueFlowPeer)
                memset(packet + 20, (int) repeat, 4);
            require(runPacket(packet, sizeof(packet)) == stable_queue,
                    "stable prefix ignores later bytes and peer ignores every payload byte");
        }
        reverseEndpoints(packet, 20);
        require(runPacket(packet, sizeof(packet)) == stable_queue,
                "opaque receive key is symmetric in associated endpoint words");
        reverseEndpoints(packet, 20);

        /* Options move the prefix; bytes from the IP header never become words. */
        makePacket(packet, sizeof(packet), protocols[p]);
        memmove(packet + 24, packet + 20, sizeof(packet) - 24);
        memset(packet + 20, 0xA5, 4);
        packet[0] = 0x46;
        require(runPacket(packet, sizeof(packet)) == stable_queue,
                "opaque prefix follows the actual IPv4 header length");
        for (unsigned length = 0; length <= 4; ++length)
        {
            put16(packet + 2, (uint16_t) (24 + length));
            const uint32_t expected =
                length < 4 || opaque_mode == kDeviceOpaqueFlowPeer ? addressQueue(packet) : stable_queue;
            require(runPacket(packet, sizeof(packet)) == expected && runPacket(packet, 24 + length) == expected,
                    "opaque short payload uses fallback and trailing buffer bytes are never a prefix");
        }

        makePacket(packet, sizeof(packet), protocols[p]);
        for (unsigned prefix = 0; prefix < 512; ++prefix)
        {
            put16(packet + 20, (uint16_t) (prefix ^ 0x5AA5));
            put16(packet + 22, (uint16_t) ((prefix * 17U) ^ 0x5AA5));
            require(deviceReceiveWorkerHash(packet, sizeof(packet), opaque_mode, &hash),
                    "fixed-XOR opaque prefix has a software receive key");
            const uint32_t queue = runPacket(packet, sizeof(packet));
            require(queue == hash % queue_count, "opaque prefix/XOR placement agrees with software");
            observed[queue] = true;
            memset(packet + 24, (int) prefix, sizeof(packet) - 24);
            require(runPacket(packet, sizeof(packet)) == queue,
                    "a fixed-XOR prefix remains stable as later payload bytes change");
        }
    }
    if (opaque_mode == kDeviceOpaqueFlowPrefix)
        requireAllQueues(observed, "varied opaque prefixes distribute across every queue");
}

/* Independent frozen expected values, also exercised at non-power-of-two counts. */
static void testFixedWorkerVectors(void)
{
    static const struct
    {
        uint32_t src, dst, hash;
        uint16_t src_word, dst_word;
        uint8_t  protocol;
        bool     fragmented;
    } vectors[] = {
        {UINT32_C(0x0A000001), UINT32_C(0x0A000002), UINT32_C(0xC4D8D18A), 40000, 443, 6, false},
        {UINT32_C(0x0A000101), UINT32_C(0x0A000102), UINT32_C(0x2DD3FCF0), 40000, 443, 6, false},
        {UINT32_C(0x0A000001), UINT32_C(0x0A000002), UINT32_C(0x45A834C1), 10000, 46539, 17, false},
        {UINT32_C(0x0A000001), UINT32_C(0x0A000002), UINT32_C(0x7978FD19), 42768, 46539, 17, false},
        {UINT32_C(0x0A000001), UINT32_C(0xC000022A), UINT32_C(0xBF156EC4), 12345, 443, 1, true},
        {UINT32_C(0x0A000001), UINT32_C(0xC9FF954B), UINT32_C(0xBDB9365E), 10000, 443, 6, false},
        {UINT32_C(0x0A000001), UINT32_C(0xC9FF954B), UINT32_C(0x89E8530B), 10001, 443, 6, false},
        {UINT32_C(0x0A000001), UINT32_C(0x000001BB), UINT32_C(0xB6878F90), 10000, 443, 6, false},
        {UINT32_C(0x0A000001), UINT32_C(0x000001BB), UINT32_C(0x82B60AA5), 10001, 443, 6, false},
    };
    for (unsigned i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i)
    {
        uint8_t packet[80];
        makePacket(packet, sizeof(packet), vectors[i].protocol);
        for (unsigned byte = 0; byte < 4; ++byte)
        {
            packet[12 + byte] = (uint8_t) (vectors[i].src >> (24U - 8U * byte));
            packet[16 + byte] = (uint8_t) (vectors[i].dst >> (24U - 8U * byte));
        }
        if (vectors[i].fragmented)
            put16(packet + 6, 0x2000);
        put16(packet + 20, vectors[i].src_word);
        put16(packet + 22, vectors[i].dst_word);
        require(runPacket(packet, sizeof(packet)) == vectors[i].hash % queue_count,
                "actual eBPF uses the frozen common32 worker vectors");
        reverseEndpoints(packet, 20);
        require(runPacket(packet, sizeof(packet)) == vectors[i].hash % queue_count,
                "frozen eBPF worker vectors retain bidirectional affinity");
    }
    if (opaque_mode != kDeviceOpaqueFlowSpread)
    {
        uint8_t packet[80];
        makePacket(packet, sizeof(packet), 253);
        const uint32_t expected = opaque_mode == kDeviceOpaqueFlowPrefix ? UINT32_C(0xA6F6867F) : UINT32_C(0xEFD3C01E);
        require(runPacket(packet, sizeof(packet)) == expected % queue_count,
                "opaque kernel policy matches its independent frozen expected vector");
    }
}

static void pinCpu(unsigned cpu)
{
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    CPU_SET(cpu, &affinity);
    require(sched_setaffinity(0, sizeof(affinity), &affinity) == 0, "pins kernel steering calls to an available CPU");
    require(sched_getcpu() == (int) cpu, "steering tests execute on the selected CPU");
}

static void testOpaqueRoundRobin(unsigned cpu)
{
    uint8_t  packet[80];
    uint64_t sequence = cpu;
    for (unsigned protocol = 0; protocol <= UINT8_MAX; ++protocol)
    {
        if (protocol == 6 || protocol == 17)
        {
            continue;
        }
        makePacket(packet, sizeof(packet), (uint8_t) protocol);
        for (unsigned repeat = 0; repeat < 2 * kRequestedQueues; ++repeat)
        {
            require(runPacket(packet, sizeof(packet)) == sequence++ % kRequestedQueues,
                    "identical opaque IPv4 packets on one CPU cycle across every queue from its CPU offset");
        }
        /* The minimum complete IPv4 datagram has no transport payload. */
        put16(packet + 2, 20);
        require(runPacket(packet, 20) == sequence++ % kRequestedQueues,
                "header-only opaque IPv4 packets share the CPU cursor across protocols");
    }

    makePacket(packet, sizeof(packet), 253);
    for (unsigned header_words = 5; header_words <= 15; ++header_words)
    {
        packet[0] = (uint8_t) (0x40 | header_words);
        put16(packet + 2, (uint16_t) (header_words * 4));
        packet[6] ^= 0x40;
        reverseEndpoints(packet, 60);
        require(runPacket(packet, header_words * 4) == sequence++ % kRequestedQueues,
                "IPv4 options, DF and endpoint direction do not change opaque round robin");
    }

    makePacket(packet, sizeof(packet), 253);
    for (unsigned length = 0; length < 20; ++length)
    {
        require(runPacket(packet, length) == 0, "truncated opaque IPv4 cannot advance round robin");
    }
    put16(packet + 2, sizeof(packet) + 1);
    require(runPacket(packet, sizeof(packet)) == 0, "truncated opaque datagrams select queue zero");
    packet[0] = 0x44;
    put16(packet + 2, sizeof(packet));
    require(runPacket(packet, sizeof(packet)) == 0, "invalid opaque IHL selects queue zero");
    packet[0] = 0x4F;
    put16(packet + 2, 59);
    require(runPacket(packet, sizeof(packet)) == 0, "opaque total length cannot end inside its options");

    /* Hash-only paths must neither consume nor reset the opaque counter. */
    testTransportSteering();
    testFragmentFallback();
    testHeaderBounds();
    makePacket(packet, sizeof(packet), 253);
    require(runPacket(packet, sizeof(packet)) == sequence % kRequestedQueues,
            "transport, fragment and invalid packets leave the opaque counter untouched");
}

static void testPerCpuCounters(unsigned first_cpu, unsigned second_cpu)
{
    uint8_t packet[80];
    makePacket(packet, sizeof(packet), 253);
    const uint32_t first_queue = runPacket(packet, sizeof(packet));

    pinCpu(second_cpu);
    const unsigned second_packets = 2 * kRequestedQueues + 3;
    for (unsigned i = 0; i < second_packets; ++i)
    {
        require(runPacket(packet, sizeof(packet)) == (second_cpu + i) % kRequestedQueues,
                "a previously unused CPU starts its own cursor and cycles from its CPU offset");
    }
    pinCpu(first_cpu);
    require(runPacket(packet, sizeof(packet)) == (first_queue + 1) % kRequestedQueues,
            "another CPU's traffic does not advance or reset the first CPU's cursor");
    pinCpu(second_cpu);
    require(runPacket(packet, sizeof(packet)) == (second_cpu + second_packets) % kRequestedQueues,
            "returning to the second CPU resumes its independent cursor");
    pinCpu(first_cpu);
}

static void testIndependentCounters(unsigned cpu)
{
    uint8_t packet[80];
    makePacket(packet, sizeof(packet), 253);
    const int      first_program = kernel_fd;
    const uint32_t first_queue   = runPacket(packet, sizeof(packet));

    reset();
    int         fds[kRequestedQueues];
    const char *reason;
    require(openQueues(kRequestedQueues, fds, &reason) == kRequestedQueues,
            "a second interface gets its own loaded steering program");
    require(runPacket(packet, sizeof(packet)) == cpu % kRequestedQueues &&
                runPacket(packet, sizeof(packet)) == (cpu + 1) % kRequestedQueues,
            "each interface starts separate zero-initialized CPU cursors with the same CPU offset");
    __real_close(kernel_fd);
    kernel_fd = first_program;
    require(runPacket(packet, sizeof(packet)) == (first_queue + 1) % kRequestedQueues,
            "creating and destroying another interface does not reset or advance the first counter");
}

static bool openKernelProgram(device_opaque_flow_mode_t mode, uint16_t count)
{
    reset();
    run_kernel  = true;
    opaque_mode = mode;
    int         fds[254];
    const char *reason;
    if (openQueues(count, fds, &reason) != count)
    {
        if (errno == EPERM || errno == EACCES || errno == ENOSYS)
        {
            fprintf(stderr,
                    "SKIP: kernel BPF %s program unavailable: %s (%s)\n",
                    deviceOpaqueFlowModeName(mode),
                    reason,
                    strerror(errno));
            return false;
        }
        require(false, "production steering passes the actual kernel verifier");
    }
    return true;
}

static bool testIndependentModes(void)
{
    require(opaque_mode == kDeviceOpaqueFlowPrefix, "first independent interface uses prefix mode");
    uint8_t packet[80];
    makePacket(packet, sizeof(packet), 253);
    uint32_t prefix_queue = runPacket(packet, sizeof(packet));
    for (unsigned word = 1; word <= 512 && prefix_queue == addressQueue(packet); ++word)
    {
        put16(packet + 20, (uint16_t) word);
        prefix_queue = runPacket(packet, sizeof(packet));
    }
    require(prefix_queue != addressQueue(packet), "mode-isolation packet distinguishes prefix from peer");
    const int prefix_program = kernel_fd;
    if (! openKernelProgram(kDeviceOpaqueFlowPeer, kRequestedQueues))
    {
        __real_close(prefix_program);
        return false;
    }
    require(runPacket(packet, sizeof(packet)) == addressQueue(packet),
            "a separate peer interface ignores the prefix used by the first interface");
    __real_close(kernel_fd);
    kernel_fd   = prefix_program;
    opaque_mode = kDeviceOpaqueFlowPrefix;
    require(runPacket(packet, sizeof(packet)) == prefix_queue,
            "another interface's mode does not change the first interface's policy");
    return true;
}

static int testKernel(void)
{
    cpu_set_t original_affinity;
    require(sched_getaffinity(0, sizeof(original_affinity), &original_affinity) == 0,
            "discovers the CPUs available to this test");
    int first_cpu  = -1;
    int second_cpu = -1;
    for (unsigned cpu = 0; cpu < CPU_SETSIZE; ++cpu)
    {
        if (CPU_ISSET(cpu, &original_affinity))
        {
            if (first_cpu < 0)
            {
                first_cpu = (int) cpu;
            }
            else
            {
                second_cpu = (int) cpu;
                break;
            }
        }
    }
    require(first_cpu >= 0, "the test has an available CPU");
    pinCpu((unsigned) first_cpu);
    const device_opaque_flow_mode_t modes[] = {kDeviceOpaqueFlowPrefix, kDeviceOpaqueFlowPeer, kDeviceOpaqueFlowSpread};
    const uint16_t                  counts[] = {3, 7, 16, 254};
    for (unsigned m = 0; m < sizeof(modes) / sizeof(modes[0]); ++m)
    {
        for (unsigned c = 0; c < sizeof(counts) / sizeof(counts[0]); ++c)
        {
            if (! openKernelProgram(modes[m], counts[c]))
                return 77;
            testFixedWorkerVectors();
            __real_close(kernel_fd);
            kernel_fd = -1;
        }
        if (! openKernelProgram(modes[m], kRequestedQueues))
            return 77;
        if (modes[m] == kDeviceOpaqueFlowSpread)
        {
            testOpaqueRoundRobin((unsigned) first_cpu);
            if (second_cpu >= 0)
                testPerCpuCounters((unsigned) first_cpu, (unsigned) second_cpu);
            testIndependentCounters((unsigned) first_cpu);
        }
        else
        {
            testTransportSteering();
            testFragmentFallback();
            testHeaderBounds();
            testOpaqueDeterministic();
            if (modes[m] == kDeviceOpaqueFlowPrefix && ! testIndependentModes())
                return 77;
        }
        __real_close(kernel_fd);
        kernel_fd = -1;
    }
    require(sched_setaffinity(0, sizeof(original_affinity), &original_affinity) == 0,
            "restores the original CPU affinity after steering tests");
    if (second_cpu < 0)
    {
        fprintf(stderr, "SKIP: local cycling passed, but per-CPU independence requires two available CPUs\n");
        return 77;
    }
    return 0;
}

int main(int argc, char **argv)
{
    testCaseSet("tun_linux_queues_test");
    if (argc == 2 && strcmp(argv[1], "--kernel") == 0)
    {
        return testKernel();
    }
    testSetup();
    return 0;
}
