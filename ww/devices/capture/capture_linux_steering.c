#include "capture_linux_steering.h"

#include <assert.h>
#include <linux/filter.h>
#include <linux/netfilter/xt_bpf.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

// /* The generated programs carry exactly two protocol compares; a larger set needs new instruction slots. */
// _Static_assert(kCaptureLinuxPortedProtocols == 2,
//                "the steering and opaque programs hard-code two ported-protocol slots");

// void captureLinuxBuildSteeringFilter(uint16_t queue_count, uint16_t lane_index, const uint8_t *ported_protocols,
//                                      unsigned ported_count, char output[kCaptureLinuxSteeringFilterSize])
// void captureLinuxBuildSteeringFilter(uint16_t queue_count, uint16_t lane_index, bool opaque_lanes,
//                                      char output[kCaptureLinuxSteeringFilterSize])
{
    assert(queue_count > 0 && lane_index < queue_count);
    assert(output != NULL && ported_count <= kCaptureLinuxPortedProtocols);
    assert(ported_protocols != NULL || ported_count == 0);
    /* A ported protocol slot compares the IP protocol byte with its number; an unused slot holds 256 and never matches.
     */
    uint32_t ported[kCaptureLinuxPortedProtocols];
    for (unsigned i = 0; i < kCaptureLinuxPortedProtocols; ++i)
        ported[i] = i < ported_count ? ported_protocols[i] : 256U;

    /* Scratch words: IPv4 header length, declared packet length, running hash,
     * source port. Explicit length checks keep out-of-bounds loads from silently
     * rejecting malformed input in every lane (native cBPF returns zero there).
     * Short but otherwise valid transport payloads retain address-only steering. */
    typedef struct capture_steering_program_s
    {
        struct sock_filter header[15];
        struct sock_filter addresses[10];
        struct sock_filter fragments[2];
        struct sock_filter transport[5];
        struct sock_filter ports[16];
        struct sock_filter mix[14];
        struct sock_filter match[1];
        struct sock_filter none[1];
    } capture_steering_program_t;
#define CAPTURE_BPF_SKIP(from, target)                                                                                 \
    ((uint8_t) ((offsetof(capture_steering_program_t, target) - offsetof(capture_steering_program_t, from)) /          \
                    sizeof(struct sock_filter) -                                                                       \
                1U))
    /* Malformed input selects lane zero for ordinary validation: lane zero jumps to the tail match, every other lane to
     * the tail miss. */
#define CAPTURE_BPF_INVALID(from) (lane_index == 0 ? CAPTURE_BPF_SKIP(from, match) : CAPTURE_BPF_SKIP(from, none))
    const capture_steering_program_t program = {
        .header =
            {
                BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),
                BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 20, 0, CAPTURE_BPF_INVALID(header[1])),
                BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0),
                BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, 4),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 4, 0, CAPTURE_BPF_INVALID(header[4])),
                BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0),
                BPF_STMT(BPF_STX, 0),
                BPF_STMT(BPF_MISC | BPF_TXA, 0),
                BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 20, 0, CAPTURE_BPF_INVALID(header[8])),
                BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 2),
                BPF_JUMP(BPF_JMP | BPF_JGE | BPF_X, 0, 0, CAPTURE_BPF_INVALID(header[10])),
                BPF_STMT(BPF_ST, 1),
                BPF_STMT(BPF_MISC | BPF_TAX, 0),
                BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),
                BPF_JUMP(BPF_JMP | BPF_JGE | BPF_X, 0, 0, CAPTURE_BPF_INVALID(header[14])),
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
//                 BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ported[0], CAPTURE_BPF_SKIP(transport[2], ports), 0),
//                 BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ported[1], CAPTURE_BPF_SKIP(transport[3], ports), 0),
//                 BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 17, 0, CAPTURE_BPF_SKIP(transport[4], none)),
//                 /* Opaque lanes reuse the address/protocol hash, so one ordered
//                  * encapsulating stream (an ICMP or GRE tunnel) stays on one queue. */
//                 BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
//                          17,
//                          0,
//                          opaque_lanes ? CAPTURE_BPF_SKIP(transport[2], mix) : CAPTURE_BPF_SKIP(transport[2], opaque)),
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
            },
        .match = {BPF_STMT(BPF_RET | BPF_K, 1)},
        .none  = {BPF_STMT(BPF_RET | BPF_K, 0)},
    };
#undef CAPTURE_BPF_INVALID
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

void captureLinuxBuildOpaqueFilter(const uint8_t *ported_protocols, unsigned ported_count,
                                   char output[kCaptureLinuxSteeringFilterSize])
{
    assert(output != NULL && ported_count <= kCaptureLinuxPortedProtocols);
    assert(ported_protocols != NULL || ported_count == 0);
    /* Complement of flow steering for structurally valid, unfragmented IPv4 that is neither TCP/UDP nor a ported
     * protocol. All fragments retain their existing receive/processing association. Every rejection jumps to the final
     * RET 0; an unused ported slot holds 256 and never matches. */
    enum
    {
        kCount  = 22,
        kReject = kCount - 1
    };
#define CAPTURE_OPAQUE_REJECT(index) ((uint8_t) (kReject - (index) - 1))
    uint32_t ported[kCaptureLinuxPortedProtocols];
    for (unsigned i = 0; i < kCaptureLinuxPortedProtocols; ++i)
        ported[i] = i < ported_count ? ported_protocols[i] : 256U;
    const struct sock_filter program[kCount] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 20, 0, CAPTURE_OPAQUE_REJECT(1)),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0),
        BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 4, 0, CAPTURE_OPAQUE_REJECT(4)),
        BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0),
        BPF_STMT(BPF_MISC | BPF_TXA, 0),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 20, 0, CAPTURE_OPAQUE_REJECT(7)),
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 2),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_X, 0, 0, CAPTURE_OPAQUE_REJECT(9)),
        BPF_STMT(BPF_MISC | BPF_TAX, 0),
        BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_X, 0, 0, CAPTURE_OPAQUE_REJECT(12)),
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 6),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x3fff, CAPTURE_OPAQUE_REJECT(14), 0),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 9),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6, CAPTURE_OPAQUE_REJECT(16), 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 17, CAPTURE_OPAQUE_REJECT(17), 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ported[0], CAPTURE_OPAQUE_REJECT(18), 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ported[1], CAPTURE_OPAQUE_REJECT(19), 0),
        BPF_STMT(BPF_RET | BPF_K, 1),
        BPF_STMT(BPF_RET | BPF_K, 0),
    };
#undef CAPTURE_OPAQUE_REJECT
    size_t used = (size_t) snprintf(output, kCaptureLinuxSteeringFilterSize, "%u", (unsigned int) kCount);
    for (unsigned i = 0; i < kCount; ++i)
        used += (size_t) snprintf(output + used,
                                  kCaptureLinuxSteeringFilterSize - used,
                                  ",%u %u %u %u",
                                  (unsigned int) program[i].code,
                                  (unsigned int) program[i].jt,
                                  (unsigned int) program[i].jf,
                                  program[i].k);
}
