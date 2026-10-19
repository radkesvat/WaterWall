#include "tun_linux_queues.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Socket-filter absolute loads preserve R6..R9 and return network byte order
 * fields as host integers. A truncated load exits with zero. TUN's steering
 * hook sees the raw IP packet, before the optional virtio header is prepended.
 *
 * Queue selection deliberately ignores transport ports and IP identification:
 * every ordinary packet and fragment sharing an IPv4 endpoint pair/protocol
 * must have the same single receive producer. WaterWall's full flow hash still
 * chooses the processing worker after fragment handling. Explicit steering also
 * bypasses the kernel's write-learned queue migration. Unsupported IP versions
 * share queue zero. No helper, BPF map, external compiler or libbpf is needed. */
#define TUN_BPF_INSN(op, dst, src, offset, value)                                                                      \
    {.code = (op), .dst_reg = (dst), .src_reg = (src), .off = (offset), .imm = (value)}

static int tunLinuxSteeringLoad(uint16_t count)
{
#if defined(SYS_bpf) && defined(TUNSETSTEERINGEBPF)
    const struct bpf_insn program[] = {
        TUN_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_1, 0, 0),
        TUN_BPF_INSN(BPF_LD | BPF_ABS | BPF_B, 0, 0, 0, 0),
        TUN_BPF_INSN(BPF_ALU | BPF_RSH | BPF_K, BPF_REG_0, 0, 0, 4),
        TUN_BPF_INSN(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 2, 4),
        TUN_BPF_INSN(BPF_ALU | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
        TUN_BPF_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        TUN_BPF_INSN(BPF_LD | BPF_ABS | BPF_W, 0, 0, 0, 12),
        TUN_BPF_INSN(BPF_ALU | BPF_MOV | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
        TUN_BPF_INSN(BPF_LD | BPF_ABS | BPF_W, 0, 0, 0, 16),
        TUN_BPF_INSN(BPF_ALU | BPF_XOR | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
        TUN_BPF_INSN(BPF_LD | BPF_ABS | BPF_B, 0, 0, 0, 9),
        TUN_BPF_INSN(BPF_ALU | BPF_MUL | BPF_K, BPF_REG_0, 0, 0, (int32_t) UINT32_C(0x9E3779B1)),
        TUN_BPF_INSN(BPF_ALU | BPF_XOR | BPF_X, BPF_REG_0, BPF_REG_7, 0, 0),
        TUN_BPF_INSN(BPF_ALU | BPF_MOV | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
        TUN_BPF_INSN(BPF_ALU | BPF_RSH | BPF_K, BPF_REG_7, 0, 0, 16),
        TUN_BPF_INSN(BPF_ALU | BPF_XOR | BPF_X, BPF_REG_0, BPF_REG_7, 0, 0),
        TUN_BPF_INSN(BPF_ALU | BPF_MUL | BPF_K, BPF_REG_0, 0, 0, (int32_t) UINT32_C(0x7FEB352D)),
        TUN_BPF_INSN(BPF_ALU | BPF_MOV | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
        TUN_BPF_INSN(BPF_ALU | BPF_RSH | BPF_K, BPF_REG_7, 0, 0, 15),
        TUN_BPF_INSN(BPF_ALU | BPF_XOR | BPF_X, BPF_REG_0, BPF_REG_7, 0, 0),
        TUN_BPF_INSN(BPF_ALU | BPF_MUL | BPF_K, BPF_REG_0, 0, 0, (int32_t) UINT32_C(0x846CA68B)),
        TUN_BPF_INSN(BPF_ALU | BPF_MOV | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
        TUN_BPF_INSN(BPF_ALU | BPF_RSH | BPF_K, BPF_REG_7, 0, 0, 16),
        TUN_BPF_INSN(BPF_ALU | BPF_XOR | BPF_X, BPF_REG_0, BPF_REG_7, 0, 0),
        TUN_BPF_INSN(BPF_ALU | BPF_MOD | BPF_K, BPF_REG_0, 0, 0, count),
        TUN_BPF_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    };
    static const char license[] = "GPL";
    union bpf_attr    attr      = {0};
    attr.prog_type              = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt               = (uint32_t) (sizeof(program) / sizeof(program[0]));
    attr.insns                  = (uint64_t) (uintptr_t) program;
    attr.license                = (uint64_t) (uintptr_t) license;
    return (int) syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
#else
    (void) count;
    errno = ENOSYS;
    return -1;
#endif
}

#undef TUN_BPF_INSN

uint16_t tunLinuxQueuesOpen(int first_fd, const char *name, bool checksum_setup, uint16_t requested_count, int *out_fds,
                            const char **out_reason)
{
    assert(first_fd >= 0);
    assert(name != NULL);
    assert(requested_count > 0);
    assert(out_fds != NULL);
    assert(out_reason != NULL);
    *out_reason = NULL;
    out_fds[0]  = first_fd;
    for (uint16_t i = 1; i < requested_count; ++i)
    {
        out_fds[i] = -1;
    }
    if (requested_count == 1)
    {
        return 1;
    }

    struct ifreq existing = {0};
    if (ioctl(first_fd, TUNGETIFF, &existing) < 0)
    {
        *out_reason = "checking multiqueue device flags";
        return 1;
    }
    if ((existing.ifr_flags & IFF_MULTI_QUEUE) == 0)
    {
        *out_reason = "IFF_MULTI_QUEUE unavailable";
        errno       = EOPNOTSUPP;
        return 1;
    }

    int steering_fd = tunLinuxSteeringLoad(requested_count);
    if (steering_fd < 0)
    {
        *out_reason = "loading stable multiqueue steering";
        return 1;
    }
#ifdef TUNSETSTEERINGEBPF
    const int steering_result = ioctl(first_fd, TUNSETSTEERINGEBPF, &steering_fd);
    const int steering_errno  = errno;
    close(steering_fd);
    if (steering_result < 0)
    {
        *out_reason = "installing stable multiqueue steering";
        errno       = steering_errno;
        return 1;
    }
#else
    close(steering_fd);
    *out_reason = "stable multiqueue steering unavailable";
    errno       = ENOSYS;
    return 1;
#endif

    uint16_t opened = 1;
    for (; opened < requested_count; ++opened)
    {
        int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0)
        {
            *out_reason = "opening extra TUN queue";
            break;
        }
        struct ifreq request = {0};
        request.ifr_flags    = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE | (checksum_setup ? IFF_VNET_HDR : 0);
        strncpy(request.ifr_name, name, IFNAMSIZ - 1);
        if (ioctl(fd, TUNSETIFF, &request) < 0)
        {
            const int saved_errno = errno;
            close(fd);
            *out_reason = "attaching extra TUN queue";
            errno       = saved_errno;
            break;
        }
        out_fds[opened] = fd;
    }
    if (opened == requested_count)
    {
        return requested_count;
    }

    const int saved_errno = errno;
    while (opened > 1)
    {
        --opened;
        close(out_fds[opened]);
        out_fds[opened] = -1;
    }
    /* Keep the installed steering program. With one attached queue the kernel's
     * final modulo always selects zero. It is freed with the owned interface. */
    errno = saved_errno;
    return 1;
}
