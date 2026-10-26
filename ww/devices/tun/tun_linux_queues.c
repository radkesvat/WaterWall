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

/* Packet loads preserve R6..R9 and return network fields in host byte order.
 * R6 holds the skb until the final load. Ordinary IPv4 TCP/UDP uses the same
 * symmetric endpoint hash as deviceFlowAffinityHash(), aligning receive queues
 * with initial processing workers. All fragments use the address/protocol fallback:
 * later fragments have no ports. Fragmented and ordinary packets of one flow
 * can therefore have different readers. The shared table retains fragment locality
 * or reassembles input; stateful consumers establish their own flow ownership.
 * Complete opaque IPv4 packets use approximate round robin
 * with an interface-local cursor per CPU. Unsupported IP versions use queue zero.
 * Explicit steering bypasses kernel write-learned queue migration. */
#define TUN_BPF_INSN(op, dst, src, offset, value)                                                                      \
    {.code = (op), .dst_reg = (dst), .src_reg = (src), .off = (offset), .imm = (value)}

#define TUN_BPF_CONST64(dst, value)                                                                                    \
    TUN_BPF_INSN(BPF_LD | BPF_DW | BPF_IMM, dst, 0, 0, (int32_t) (uint32_t) UINT64_C(value)),                          \
        TUN_BPF_INSN(0, 0, 0, 0, (int32_t) (UINT64_C(value) >> 32U))

/* Mix R0 using R1 and R6 as scratch, matching deviceFlowAffinityMix64(). */
#define TUN_BPF_MIX64                                                                                                  \
    TUN_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_1, BPF_REG_0, 0, 0),                                             \
        TUN_BPF_INSN(BPF_ALU64 | BPF_RSH | BPF_K, BPF_REG_1, 0, 0, 30),                                                \
        TUN_BPF_INSN(BPF_ALU64 | BPF_XOR | BPF_X, BPF_REG_0, BPF_REG_1, 0, 0),                                         \
        TUN_BPF_CONST64(BPF_REG_6, 0xBF58476D1CE4E5B9),                                                                \
        TUN_BPF_INSN(BPF_ALU64 | BPF_MUL | BPF_X, BPF_REG_0, BPF_REG_6, 0, 0),                                         \
        TUN_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_1, BPF_REG_0, 0, 0),                                         \
        TUN_BPF_INSN(BPF_ALU64 | BPF_RSH | BPF_K, BPF_REG_1, 0, 0, 27),                                                \
        TUN_BPF_INSN(BPF_ALU64 | BPF_XOR | BPF_X, BPF_REG_0, BPF_REG_1, 0, 0),                                         \
        TUN_BPF_CONST64(BPF_REG_6, 0x94D049BB133111EB),                                                                \
        TUN_BPF_INSN(BPF_ALU64 | BPF_MUL | BPF_X, BPF_REG_0, BPF_REG_6, 0, 0),                                         \
        TUN_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_1, BPF_REG_0, 0, 0),                                         \
        TUN_BPF_INSN(BPF_ALU64 | BPF_RSH | BPF_K, BPF_REG_1, 0, 0, 31),                                                \
        TUN_BPF_INSN(BPF_ALU64 | BPF_XOR | BPF_X, BPF_REG_0, BPF_REG_1, 0, 0)

static int tunLinuxSteeringLoad(uint16_t count)
{
#if defined(SYS_bpf) && defined(TUNSETSTEERINGEBPF)
    union bpf_attr map_attr = {0};
    map_attr.map_type       = BPF_MAP_TYPE_PERCPU_ARRAY;
    map_attr.key_size       = sizeof(uint32_t);
    map_attr.value_size     = sizeof(uint32_t);
    map_attr.max_entries    = 1;
    const int counter_fd    = (int) syscall(SYS_bpf, BPF_MAP_CREATE, &map_attr, sizeof(map_attr));
    if (counter_fd < 0)
    {
        return -1;
    }

    /* Named sections keep forward jumps independent of hash instruction count. */
    typedef struct tun_linux_steering_program_s
    {
        struct bpf_insn entry[8];
        struct bpf_insn header[7];
        struct bpf_insn fragments[2];
        struct bpf_insn transport[7];
        struct bpf_insn endpoints[9];
        struct bpf_insn protocol[2];
        struct bpf_insn flow_hash[82];
        struct bpf_insn fallback[20];
        struct bpf_insn opaque[16];
        struct bpf_insn invalid[2];
    } tun_linux_steering_program_t;
#define TUN_BPF_SKIP(from, target)                                                                                     \
    ((int16_t) ((offsetof(tun_linux_steering_program_t, target) - offsetof(tun_linux_steering_program_t, from)) /      \
                    sizeof(struct bpf_insn) -                                                                          \
                1U))
    const tun_linux_steering_program_t program = {
        .entry =
            {
                TUN_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_1, 0, 0),
                TUN_BPF_INSN(BPF_LD | BPF_ABS | BPF_B, 0, 0, 0, 0),
                TUN_BPF_INSN(BPF_ALU | BPF_MOV | BPF_X, BPF_REG_9, BPF_REG_0, 0, 0),
                TUN_BPF_INSN(BPF_ALU | BPF_RSH | BPF_K, BPF_REG_0, 0, 0, 4),
                TUN_BPF_INSN(BPF_JMP | BPF_JNE | BPF_K, BPF_REG_0, 0, TUN_BPF_SKIP(entry[4], invalid), 4),
                TUN_BPF_INSN(BPF_ALU | BPF_AND | BPF_K, BPF_REG_9, 0, 0, 0x0f),
                TUN_BPF_INSN(BPF_ALU | BPF_LSH | BPF_K, BPF_REG_9, 0, 0, 2),
                TUN_BPF_INSN(BPF_JMP | BPF_JLT | BPF_K, BPF_REG_9, 0, TUN_BPF_SKIP(entry[7], invalid), 20),
            },
        .header =
            {
                TUN_BPF_INSN(BPF_LD | BPF_ABS | BPF_H, 0, 0, 0, 2),
                TUN_BPF_INSN(BPF_JMP | BPF_JLT | BPF_X, BPF_REG_0, BPF_REG_9, TUN_BPF_SKIP(header[1], invalid), 0),
                TUN_BPF_INSN(BPF_ALU | BPF_MOV | BPF_X, BPF_REG_8, BPF_REG_0, 0, 0),
                TUN_BPF_INSN(BPF_ALU | BPF_MOV | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
                TUN_BPF_INSN(BPF_ALU | BPF_SUB | BPF_K, BPF_REG_7, 0, 0, 1),
                /* An out-of-bounds packet load exits with zero. Probe the final
                 * declared byte before reading any transport fields. */
                TUN_BPF_INSN(BPF_LD | BPF_IND | BPF_B, 0, BPF_REG_7, 0, 0),
                TUN_BPF_INSN(BPF_LD | BPF_ABS | BPF_H, 0, 0, 0, 6),
            },
        .fragments =
            {
                TUN_BPF_INSN(BPF_ALU | BPF_AND | BPF_K, BPF_REG_0, 0, 0, 0x3fff),
                TUN_BPF_INSN(BPF_JMP | BPF_JNE | BPF_K, BPF_REG_0, 0, TUN_BPF_SKIP(fragments[1], fallback), 0),
            },
        .transport =
            {
                TUN_BPF_INSN(BPF_LD | BPF_ABS | BPF_B, 0, 0, 0, 9),
                TUN_BPF_INSN(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 1, 6),
                TUN_BPF_INSN(BPF_JMP | BPF_JNE | BPF_K, BPF_REG_0, 0, TUN_BPF_SKIP(transport[2], opaque), 17),
                TUN_BPF_INSN(BPF_ALU | BPF_MOV | BPF_X, BPF_REG_0, BPF_REG_9, 0, 0),
                TUN_BPF_INSN(BPF_ALU | BPF_ADD | BPF_K, BPF_REG_0, 0, 0, 4),
                TUN_BPF_INSN(BPF_JMP | BPF_JLT | BPF_X, BPF_REG_8, BPF_REG_0, TUN_BPF_SKIP(transport[5], fallback), 0),
                TUN_BPF_INSN(BPF_LD | BPF_IND | BPF_H, 0, BPF_REG_9, 0, 0),
            },
        .endpoints =
            {
                TUN_BPF_INSN(BPF_ALU | BPF_MOV | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
                TUN_BPF_INSN(BPF_LD | BPF_ABS | BPF_W, 0, 0, 0, 12),
                TUN_BPF_INSN(BPF_ALU64 | BPF_LSH | BPF_K, BPF_REG_0, 0, 0, 16),
                TUN_BPF_INSN(BPF_ALU64 | BPF_OR | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
                TUN_BPF_INSN(BPF_LD | BPF_IND | BPF_H, 0, BPF_REG_9, 0, 2),
                TUN_BPF_INSN(BPF_ALU | BPF_MOV | BPF_X, BPF_REG_8, BPF_REG_0, 0, 0),
                TUN_BPF_INSN(BPF_LD | BPF_ABS | BPF_W, 0, 0, 0, 16),
                TUN_BPF_INSN(BPF_ALU64 | BPF_LSH | BPF_K, BPF_REG_0, 0, 0, 16),
                TUN_BPF_INSN(BPF_ALU64 | BPF_OR | BPF_X, BPF_REG_8, BPF_REG_0, 0, 0),
            },
        .protocol =
            {
                TUN_BPF_INSN(BPF_LD | BPF_ABS | BPF_B, 0, 0, 0, 9),
                TUN_BPF_INSN(BPF_ALU | BPF_MOV | BPF_X, BPF_REG_9, BPF_REG_0, 0, 0),
            },
        .flow_hash =
            {
                /* Canonicalize the packed (address << 16) | port endpoints. */
                TUN_BPF_INSN(BPF_JMP | BPF_JLE | BPF_X, BPF_REG_7, BPF_REG_8, 3, 0),
                TUN_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_0, BPF_REG_7, 0, 0),
                TUN_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_7, BPF_REG_8, 0, 0),
                TUN_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_8, BPF_REG_0, 0, 0),
                TUN_BPF_CONST64(BPF_REG_6, 0x9E3779B97F4A7C15),
                TUN_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_0, BPF_REG_7, 0, 0),
                TUN_BPF_INSN(BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_0, BPF_REG_6, 0, 0),
                TUN_BPF_MIX64,
                TUN_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
                TUN_BPF_CONST64(BPF_REG_6, 0xD1B54A32D192ED03),
                TUN_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_0, BPF_REG_8, 0, 0),
                TUN_BPF_INSN(BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_0, BPF_REG_6, 0, 0),
                TUN_BPF_MIX64,
                TUN_BPF_INSN(BPF_ALU64 | BPF_XOR | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
                TUN_BPF_CONST64(BPF_REG_6, 0x94D049BB133111EB),
                TUN_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_0, BPF_REG_9, 0, 0),
                TUN_BPF_INSN(BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_0, BPF_REG_6, 0, 0),
                TUN_BPF_MIX64,
                TUN_BPF_INSN(BPF_ALU64 | BPF_XOR | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
                TUN_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_0, BPF_REG_7, 0, 0),
                TUN_BPF_MIX64,
                TUN_BPF_INSN(BPF_ALU64 | BPF_MOD | BPF_K, BPF_REG_0, 0, 0, count),
                TUN_BPF_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
            },
        .fallback =
            {
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
            },
        .opaque =
            {
                TUN_BPF_INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, counter_fd),
                TUN_BPF_INSN(0, 0, 0, 0, 0),
                TUN_BPF_INSN(BPF_ST | BPF_W | BPF_MEM, BPF_REG_10, 0, -4, 0),
                TUN_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
                TUN_BPF_INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -4),
                TUN_BPF_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
                TUN_BPF_INSN(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, TUN_BPF_SKIP(opaque[6], invalid), 0),
                /* Ordinary loads/stores avoid shared atomic contention. The
                 * cursor stays bounded; nested updates may lose a step, which
                 * is acceptable for this approximate packet distribution. */
                TUN_BPF_INSN(BPF_LDX | BPF_W | BPF_MEM, BPF_REG_7, BPF_REG_0, 0, 0),
                TUN_BPF_INSN(BPF_ALU | BPF_MOV | BPF_X, BPF_REG_1, BPF_REG_7, 0, 0),
                TUN_BPF_INSN(BPF_ALU | BPF_ADD | BPF_K, BPF_REG_1, 0, 0, 1),
                TUN_BPF_INSN(BPF_ALU | BPF_MOD | BPF_K, BPF_REG_1, 0, 0, count),
                TUN_BPF_INSN(BPF_STX | BPF_W | BPF_MEM, BPF_REG_0, BPF_REG_1, 0, 0),
                /* CPU offsets avoid making every CPU begin at queue zero. */
                TUN_BPF_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_smp_processor_id),
                TUN_BPF_INSN(BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_0, BPF_REG_7, 0, 0),
                TUN_BPF_INSN(BPF_ALU64 | BPF_MOD | BPF_K, BPF_REG_0, 0, 0, count),
                TUN_BPF_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
            },
        .invalid =
            {
                TUN_BPF_INSN(BPF_ALU | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
                TUN_BPF_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
            },
    };
#undef TUN_BPF_SKIP
    static const char license[] = "GPL";
    union bpf_attr    attr      = {0};
    attr.prog_type              = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt               = (uint32_t) (sizeof(program) / sizeof(struct bpf_insn));
    attr.insns                  = (uint64_t) (uintptr_t) &program;
    attr.license                = (uint64_t) (uintptr_t) license;
    const int program_fd        = (int) syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    const int load_errno        = errno;
    /* A loaded program owns its per-CPU map until interface teardown. */
    close(counter_fd);
    errno = load_errno;
    return program_fd;
#else
    (void) count;
    errno = ENOSYS;
    return -1;
#endif
}

#undef TUN_BPF_MIX64
#undef TUN_BPF_CONST64
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
