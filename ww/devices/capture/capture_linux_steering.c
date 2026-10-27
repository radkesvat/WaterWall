#include "capture_linux_steering.h"

#include <assert.h>
#include <linux/filter.h>
#include <linux/netfilter/xt_bpf.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

void captureLinuxBuildSteeringFilter(uint16_t queue_count, uint16_t lane_index, bool opaque_lanes,
                                     char output[kCaptureLinuxSteeringFilterSize])
{
    assert(queue_count > 0 && lane_index < queue_count);
    assert(output != NULL);

    /* Scratch words: IPv4 header length, declared packet length, running hash,
     * source port. Explicit length checks keep out-of-bounds loads from silently
     * rejecting malformed input in every lane (native cBPF returns zero there).
     * Short but otherwise valid transport payloads retain address-only steering. */
    typedef struct capture_steering_program_s
    {
        struct sock_filter header[15];
        struct sock_filter addresses[10];
        struct sock_filter fragments[2];
        struct sock_filter transport[3];
        struct sock_filter ports[16];
        struct sock_filter mix[16];
        struct sock_filter invalid[1];
        struct sock_filter opaque[1];
    } capture_steering_program_t;
#define CAPTURE_BPF_SKIP(from, target)                                                                                 \
    ((uint8_t) ((offsetof(capture_steering_program_t, target) - offsetof(capture_steering_program_t, from)) /          \
                    sizeof(struct sock_filter) -                                                                       \
                1U))
    const capture_steering_program_t program = {
        .header =
            {
                BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),
                BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 20, 0, CAPTURE_BPF_SKIP(header[1], invalid)),
                BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0),
                BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, 4),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 4, 0, CAPTURE_BPF_SKIP(header[4], invalid)),
                BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0),
                BPF_STMT(BPF_STX, 0),
                BPF_STMT(BPF_MISC | BPF_TXA, 0),
                BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 20, 0, CAPTURE_BPF_SKIP(header[8], invalid)),
                BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 2),
                BPF_JUMP(BPF_JMP | BPF_JGE | BPF_X, 0, 0, CAPTURE_BPF_SKIP(header[10], invalid)),
                BPF_STMT(BPF_ST, 1),
                BPF_STMT(BPF_MISC | BPF_TAX, 0),
                BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),
                BPF_JUMP(BPF_JMP | BPF_JGE | BPF_X, 0, 0, CAPTURE_BPF_SKIP(header[14], invalid)),
            },
        .addresses =
            {
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 12),
                BPF_STMT(BPF_MISC | BPF_TAX, 0),
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 16),
                BPF_STMT(BPF_ALU | BPF_XOR | BPF_X, 0),
                BPF_STMT(BPF_ST, 2),
                BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 9),
                BPF_STMT(BPF_ALU | BPF_MUL | BPF_K, UINT32_C(0x9E3779B1)),
                BPF_STMT(BPF_LDX | BPF_W | BPF_MEM, 2),
                BPF_STMT(BPF_ALU | BPF_XOR | BPF_X, 0),
                BPF_STMT(BPF_ST, 2),
            },
        .fragments =
            {
                BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 6),
                BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x3fff, CAPTURE_BPF_SKIP(fragments[1], mix), 0),
            },
        .transport =
            {
                BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 9),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6, CAPTURE_BPF_SKIP(transport[1], ports), 0),
                /* Opaque lanes reuse the address/protocol hash, so one ordered
                 * encapsulating stream (an ICMP or GRE tunnel) stays on one queue. */
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                         17,
                         0,
                         opaque_lanes ? CAPTURE_BPF_SKIP(transport[2], mix) : CAPTURE_BPF_SKIP(transport[2], opaque)),
            },
        .ports =
            {
                BPF_STMT(BPF_LD | BPF_W | BPF_MEM, 0),
                BPF_STMT(BPF_ALU | BPF_ADD | BPF_K, 4),
                BPF_STMT(BPF_MISC | BPF_TAX, 0),
                BPF_STMT(BPF_LD | BPF_W | BPF_MEM, 1),
                BPF_JUMP(BPF_JMP | BPF_JGE | BPF_X, 0, 0, CAPTURE_BPF_SKIP(ports[4], mix)),
                BPF_STMT(BPF_LDX | BPF_W | BPF_MEM, 0),
                BPF_STMT(BPF_LD | BPF_H | BPF_IND, 0),
                BPF_STMT(BPF_ALU | BPF_ADD | BPF_K, UINT32_C(0xD1B54A35)),
                BPF_STMT(BPF_ST, 3),
                BPF_STMT(BPF_LD | BPF_H | BPF_IND, 2),
                BPF_STMT(BPF_ALU | BPF_ADD | BPF_K, UINT32_C(0xD1B54A35)),
                BPF_STMT(BPF_LDX | BPF_W | BPF_MEM, 3),
                BPF_STMT(BPF_ALU | BPF_MUL | BPF_X, 0),
                BPF_STMT(BPF_LDX | BPF_W | BPF_MEM, 2),
                BPF_STMT(BPF_ALU | BPF_XOR | BPF_X, 0),
                BPF_STMT(BPF_ST, 2),
            },
        .mix =
            {
                BPF_STMT(BPF_LD | BPF_W | BPF_MEM, 2),
                BPF_STMT(BPF_MISC | BPF_TAX, 0),
                BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, 16),
                BPF_STMT(BPF_ALU | BPF_XOR | BPF_X, 0),
                BPF_STMT(BPF_ALU | BPF_MUL | BPF_K, UINT32_C(0x7FEB352D)),
                BPF_STMT(BPF_MISC | BPF_TAX, 0),
                BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, 15),
                BPF_STMT(BPF_ALU | BPF_XOR | BPF_X, 0),
                BPF_STMT(BPF_ALU | BPF_MUL | BPF_K, UINT32_C(0x846CA68B)),
                BPF_STMT(BPF_MISC | BPF_TAX, 0),
                BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, 16),
                BPF_STMT(BPF_ALU | BPF_XOR | BPF_X, 0),
                BPF_STMT(BPF_ALU | BPF_MOD | BPF_K, queue_count),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, lane_index, 0, 1),
                BPF_STMT(BPF_RET | BPF_K, 1),
                BPF_STMT(BPF_RET | BPF_K, 0),
            },
        .invalid = {BPF_STMT(BPF_RET | BPF_K, lane_index == 0 ? 1 : 0)},
        .opaque  = {BPF_STMT(BPF_RET | BPF_K, 0)},
    };
#undef CAPTURE_BPF_SKIP
    enum
    {
        kInstructionCount = sizeof(program) / sizeof(struct sock_filter)
    };
    _Static_assert(kInstructionCount <= XT_BPF_MAX_NUM_INSTR, "steering filter must fit xt_bpf");
    _Static_assert(kInstructionCount * 32 + 8 <= kCaptureLinuxSteeringFilterSize,
                   "decimal cBPF instructions must fit their fixed text buffer");

    struct sock_filter instructions[kInstructionCount];
    memcpy(instructions, &program, sizeof(instructions));
    size_t used = (size_t) snprintf(output, kCaptureLinuxSteeringFilterSize, "%u", (unsigned int) kInstructionCount);
    for (unsigned int i = 0; i < kInstructionCount; ++i)
    {
        used += (size_t) snprintf(output + used,
                                  kCaptureLinuxSteeringFilterSize - used,
                                  ",%u %u %u %u",
                                  (unsigned int) instructions[i].code,
                                  (unsigned int) instructions[i].jt,
                                  (unsigned int) instructions[i].jf,
                                  instructions[i].k);
    }
}

void captureLinuxBuildOpaqueFilter(char output[kCaptureLinuxSteeringFilterSize])
{
    /* Complement of flow steering for structurally valid, unfragmented IPv4.
     * All fragments retain their existing receive/processing association. */
    const struct sock_filter program[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 20, 0, 17),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0),
        BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 4, 0, 14),
        BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0),
        BPF_STMT(BPF_MISC | BPF_TXA, 0),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 20, 0, 11),
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 2),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_X, 0, 0, 9),
        BPF_STMT(BPF_MISC | BPF_TAX, 0),
        BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_X, 0, 0, 6),
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 6),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x3fff, 4, 0),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 9),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 17, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, 1),
        BPF_STMT(BPF_RET | BPF_K, 0),
    };
    const unsigned count = sizeof(program) / sizeof(program[0]);
    size_t         used  = (size_t) snprintf(output, kCaptureLinuxSteeringFilterSize, "%u", count);
    for (unsigned i = 0; i < count; ++i)
        used += (size_t) snprintf(output + used,
                                  kCaptureLinuxSteeringFilterSize - used,
                                  ",%u %u %u %u",
                                  program[i].code,
                                  program[i].jt,
                                  program[i].jf,
                                  program[i].k);
}
