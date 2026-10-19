/* Startup rollback and real-kernel steering invariants.
 * CTest: waterwall.tun_linux_queues_unit, waterwall.tun_linux_steering_kernel */
#include "devices/tun/tun_linux_queues.h"
#include "test_assert.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/if_tun.h>
#include <net/if.h>
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
    kQueueFdBase     = 1000,
    kRequestedQueues = 7
};

static bool     multiqueue;
static bool     checksum;
static bool     run_kernel;
static int      kernel_fd = -1;
static int      get_error;
static int      load_error;
static int      steering_error;
static unsigned open_fail_at;
static unsigned attach_fail_at;
static unsigned open_calls;
static unsigned attach_calls;
static unsigned load_calls;
static unsigned steering_calls;
static unsigned close_calls;
static int      closed[16];

int  __wrap_open(const char *path, int flags, ...);
int  __wrap_ioctl(int fd, unsigned long request, ...);
int  __wrap_close(int fd);
long __wrap_syscall(long number, ...);
long __real_syscall(long number, ...);
int  __real_close(int fd);

static void reset(void)
{
    multiqueue     = true;
    checksum       = false;
    get_error      = 0;
    load_error     = 0;
    steering_error = 0;
    open_fail_at   = 0;
    attach_fail_at = 0;
    open_calls     = 0;
    attach_calls   = 0;
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
    require(command == BPF_PROG_LOAD, "only loads one steering program");
    require(attr->prog_type == BPF_PROG_TYPE_SOCKET_FILTER, "TUN steering accepts socket-filter programs");
    require(attr->insn_cnt > 0 && attr->insn_cnt < 64, "steering is a small fixed program");
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
    return tunLinuxQueuesOpen(kFirstFd, "wwqueues", checksum, count, fds, reason);
}

static void testSetup(void)
{
    int         fds[kRequestedQueues];
    const char *reason;

    reset();
    require(openQueues(1, fds, &reason) == 1 && fds[0] == kFirstFd && reason == NULL,
            "one-worker mode needs no optional kernel facility");
    require(load_calls == 0 && open_calls == 0, "one-worker setup performs no optional work");

    reset();
    multiqueue = false;
    require(openQueues(kRequestedQueues, fds, &reason) == 1 && reason != NULL && errno == EOPNOTSUPP,
            "legacy single-queue interfaces retain one reader");
    require(load_calls == 0 && open_calls == 0, "legacy mode never changes steering");

    reset();
    get_error = ENOTTY;
    require(openQueues(kRequestedQueues, fds, &reason) == 1 && reason != NULL && errno == ENOTTY,
            "flag query failure retains the original descriptor");

    reset();
    load_error = EPERM;
    require(openQueues(kRequestedQueues, fds, &reason) == 1 && reason != NULL && errno == EPERM,
            "denied BPF permission selects single-worker fallback");
    require(steering_calls == 0 && open_calls == 0 && close_calls == 0, "no optional descriptors survive failed load");

    reset();
    steering_error = EINVAL;
    require(openQueues(kRequestedQueues, fds, &reason) == 1 && reason != NULL && errno == EINVAL,
            "unsupported steering hook selects fallback");
    require(close_calls == 1 && closed[0] == kProgramFd && open_calls == 0, "failed attach releases BPF descriptor");

    reset();
    open_fail_at = 3;
    require(openQueues(kRequestedQueues, fds, &reason) == 1 && reason != NULL && errno == EMFILE,
            "partial queue opening rolls back to one");
    require(close_calls == 3 && closed[1] == kQueueFdBase + 2 && closed[2] == kQueueFdBase + 1,
            "rollback releases extra queues in reverse order");
    for (unsigned i = 1; i < kRequestedQueues; ++i)
    {
        require(fds[i] == -1, "rolled-back and unopened outputs are invalidated");
    }

    reset();
    attach_fail_at = 2;
    require(openQueues(kRequestedQueues, fds, &reason) == 1 && reason != NULL && errno == EBUSY,
            "partial attachment failure preserves the real error");
    require(close_calls == 3 && closed[1] == kQueueFdBase + 2 && closed[2] == kQueueFdBase + 1,
            "attachment failure closes both current and prior extras");

    for (unsigned offload = 0; offload < 2; ++offload)
    {
        reset();
        checksum = offload != 0;
        require(openQueues(kRequestedQueues, fds, &reason) == kRequestedQueues && reason == NULL,
                "all queues publish only after complete setup");
        require(open_calls == kRequestedQueues - 1 && attach_calls == open_calls && close_calls == 1,
                "successful setup transfers every queue and releases the BPF descriptor");
        for (unsigned i = 1; i < kRequestedQueues; ++i)
        {
            require(fds[i] == kQueueFdBase + (int) i, "queue-index order matches descriptor order");
        }
    }
}

static uint32_t runPacket(const uint8_t *packet, uint32_t length)
{
    /* BPF_PROG_TEST_RUN removes its Ethernet header before a socket-filter
     * program runs. TUN supplies the IP payload at that same skb offset. */
    uint8_t frame[14 + 80] = {0};
    require(length <= sizeof(frame) - 14, "packet fixture fits in its Ethernet wrapper");
    frame[12] = 0x08;
    memcpy(frame + 14, packet, length);
    union bpf_attr attr    = {0};
    attr.test.prog_fd      = (uint32_t) kernel_fd;
    attr.test.data_in      = (uint64_t) (uintptr_t) frame;
    attr.test.data_size_in = 14 + length;
    attr.test.repeat       = 1;
    require(__real_syscall(SYS_bpf, BPF_PROG_TEST_RUN, &attr, sizeof(attr)) == 0,
            "kernel executes the installed production steering program");
    require(attr.test.retval < kRequestedQueues, "all packets select an attached queue");
    return attr.test.retval;
}

static int testKernel(void)
{
    reset();
    run_kernel = true;
    int         fds[kRequestedQueues];
    const char *reason;
    if (openQueues(kRequestedQueues, fds, &reason) != kRequestedQueues)
    {
        if (errno == EPERM || errno == EACCES || errno == ENOSYS)
        {
            fprintf(stderr, "SKIP: kernel BPF program load unavailable: %s (%s)\n", reason, strerror(errno));
            return 77;
        }
        require(false, "production steering passes the actual kernel verifier");
    }
    uint8_t packet[80]              = {0x45, 0, 0, sizeof(packet), 0, 0, 0x40, 0, 64, 6};
    packet[12]                      = 10;
    packet[15]                      = 1;
    packet[16]                      = 192;
    packet[17]                      = 0;
    packet[18]                      = 2;
    bool observed[kRequestedQueues] = {0};
    for (unsigned address = 1; address <= 128; ++address)
    {
        packet[19]           = (uint8_t) address;
        const uint32_t queue = runPacket(packet, sizeof(packet));
        observed[queue]      = true;
        packet[20]++;
        packet[22] += 3;
        require(runPacket(packet, sizeof(packet)) == queue, "transport ports never split a fragment-affine producer");
        packet[4]++;
        packet[6] = 0x20;
        require(runPacket(packet, sizeof(packet)) == queue, "leading fragments retain the ordinary packet's queue");
        packet[6] = 0;
        packet[7] = 8;
        require(runPacket(packet, sizeof(packet)) == queue, "nonleading fragments retain the same producer");
        packet[7] = 0;
        packet[6] = 0x40;
        uint8_t endpoint[4];
        memcpy(endpoint, packet + 12, 4);
        memcpy(packet + 12, packet + 16, 4);
        memcpy(packet + 16, endpoint, 4);
        require(runPacket(packet, sizeof(packet)) == queue, "endpoint reversal preserves queue selection");
        memcpy(packet + 16, packet + 12, 4);
        memcpy(packet + 12, endpoint, 4);
    }
    for (unsigned i = 0; i < kRequestedQueues; ++i)
    {
        require(observed[i], "distinct endpoint pairs distribute across all queues");
    }
    packet[0] = 0x60;
    require(runPacket(packet, sizeof(packet)) == 0, "unsupported IP versions retain the single designated reader");
    __real_close(kernel_fd);
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
