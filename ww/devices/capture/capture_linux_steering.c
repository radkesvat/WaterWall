#include "capture_linux_steering.h"

#include <assert.h>
#include <linux/filter.h>
#include <linux/netfilter/xt_bpf.h>
#include <stdio.h>

void captureLinuxBuildSteeringFilter(uint16_t queue_count, uint16_t lane_index, device_opaque_flow_mode_t mode,
                                     char output[kCaptureLinuxSteeringFilterSize])
{
    assert(queue_count > 0 && lane_index < queue_count);
    assert(mode >= kDeviceOpaqueFlowPrefix && mode <= kDeviceOpaqueFlowSpread);
    assert(output != NULL);
    /* Complete peer/spread programs use 64 instructions, prefix uses 61.
     * Scratch: header length, source word product then mixed source endpoint,
     * destination word product. Explicit bounds checks send invalid input to lane
     * zero instead of cBPF's implicit out-of-bounds rejection in every lane. */
    enum
    {
        kMaximumInstructions = 64
    };
    _Static_assert(kMaximumInstructions <= XT_BPF_MAX_NUM_INSTR, "steering filter must fit xt_bpf");
    _Static_assert(kMaximumInstructions * 32 + 8 <= kCaptureLinuxSteeringFilterSize,
                   "decimal cBPF instructions must fit their fixed text buffer");
    struct sock_filter program[kMaximumInstructions];
    unsigned           at = 0;
#define EMIT(code, value)                                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        assert(at < kMaximumInstructions);                                                                             \
        program[at++] = (struct sock_filter) BPF_STMT(code, value);                                                    \
    } while (0)
#define JUMP(code, value, yes, no)                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        assert(at < kMaximumInstructions);                                                                             \
        program[at++] = (struct sock_filter) BPF_JUMP(code, value, yes, no);                                           \
    } while (0)
    unsigned invalid_jumps[5];
    unsigned invalid_count = 0;
    EMIT(BPF_LD | BPF_W | BPF_LEN, 0);
    invalid_jumps[invalid_count++] = at;
    JUMP(BPF_JMP | BPF_JGE | BPF_K, 20, 0, 0);
    EMIT(BPF_LD | BPF_B | BPF_ABS, 0);
    invalid_jumps[invalid_count++] = at;
    JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x45, 0, 0);
    const unsigned bad_version = at;
    JUMP(BPF_JMP | BPF_JGT | BPF_K, 0x4f, 0, 0);
    EMIT(BPF_LDX | BPF_B | BPF_MSH, 0);
    EMIT(BPF_STX, 0);
    EMIT(BPF_LD | BPF_H | BPF_ABS, 2);
    invalid_jumps[invalid_count++] = at;
    JUMP(BPF_JMP | BPF_JGE | BPF_X, 0, 0, 0);
    EMIT(BPF_MISC | BPF_TAX, 0);
    EMIT(BPF_LD | BPF_W | BPF_LEN, 0);
    invalid_jumps[invalid_count++] = at;
    JUMP(BPF_JMP | BPF_JGE | BPF_X, 0, 0, 0);
    /* Fallback paths retain zero words; these instructions preserve X=total. */
    EMIT(BPF_LD | BPF_W | BPF_IMM, 0);
    EMIT(BPF_ST, 2);
    EMIT(BPF_ST, 3);
    EMIT(BPF_LD | BPF_H | BPF_ABS, 6);
    const unsigned fragment = at;
    JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x3fff, 0, 0);
    unsigned native = 0;
    unsigned opaque = 0;
    if (mode != kDeviceOpaqueFlowPrefix)
    {
        EMIT(BPF_LD | BPF_B | BPF_ABS, 9);
        native = at;
        JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6, 0, 0);
        opaque = at;
        JUMP(BPF_JMP | BPF_JEQ | BPF_K, 17, 0, 0);
    }
    const unsigned prefix = at;
    /* X still holds the validated total length: packet loads and protocol
     * comparisons above leave it intact. */
    EMIT(BPF_LD | BPF_W | BPF_MEM, 0);
    EMIT(BPF_ALU | BPF_ADD | BPF_K, 4);
    const unsigned short_payload = at;
    JUMP(BPF_JMP | BPF_JGT | BPF_X, 0, 0, 0);
    EMIT(BPF_LDX | BPF_W | BPF_MEM, 0);
    EMIT(BPF_LD | BPF_H | BPF_IND, 0);
    EMIT(BPF_ALU | BPF_MUL | BPF_K, UINT32_C(0x9E3779B1));
    EMIT(BPF_ST, 2);
    EMIT(BPF_LD | BPF_H | BPF_IND, 2);
    EMIT(BPF_ALU | BPF_MUL | BPF_K, UINT32_C(0x9E3779B1));
    EMIT(BPF_ST, 3);

    /* E = address XOR (word * 0x9E3779B1).
     * M(x) = ((x XOR (x >> 16)) * 0x85EBCA6B) XOR (that product >> 13).
     * Mix each complete endpoint before adding; zero cannot erase its peer. */
    const unsigned fallback = at;
    EMIT(BPF_LD | BPF_W | BPF_ABS, 12);
    EMIT(BPF_LDX | BPF_W | BPF_MEM, 2);
    EMIT(BPF_ALU | BPF_XOR | BPF_X, 0);
    EMIT(BPF_MISC | BPF_TAX, 0);
    EMIT(BPF_ALU | BPF_RSH | BPF_K, 16);
    EMIT(BPF_ALU | BPF_XOR | BPF_X, 0);
    EMIT(BPF_ALU | BPF_MUL | BPF_K, UINT32_C(0x85EBCA6B));
    EMIT(BPF_MISC | BPF_TAX, 0);
    EMIT(BPF_ALU | BPF_RSH | BPF_K, 13);
    EMIT(BPF_ALU | BPF_XOR | BPF_X, 0);
    EMIT(BPF_ST, 2);
    EMIT(BPF_LD | BPF_W | BPF_ABS, 16);
    EMIT(BPF_LDX | BPF_W | BPF_MEM, 3);
    EMIT(BPF_ALU | BPF_XOR | BPF_X, 0);
    EMIT(BPF_MISC | BPF_TAX, 0);
    EMIT(BPF_ALU | BPF_RSH | BPF_K, 16);
    EMIT(BPF_ALU | BPF_XOR | BPF_X, 0);
    EMIT(BPF_ALU | BPF_MUL | BPF_K, UINT32_C(0x85EBCA6B));
    EMIT(BPF_MISC | BPF_TAX, 0);
    EMIT(BPF_ALU | BPF_RSH | BPF_K, 13);
    EMIT(BPF_ALU | BPF_XOR | BPF_X, 0);
    EMIT(BPF_LDX | BPF_W | BPF_MEM, 2);
    EMIT(BPF_ALU | BPF_ADD | BPF_X, 0);
    EMIT(BPF_MISC | BPF_TAX, 0);
    EMIT(BPF_LD | BPF_B | BPF_ABS, 9);
    EMIT(BPF_ALU | BPF_XOR | BPF_X, 0);
    EMIT(BPF_ALU | BPF_MUL | BPF_K, UINT32_C(0x9E3779B1));
    EMIT(BPF_MISC | BPF_TAX, 0);
    EMIT(BPF_ALU | BPF_RSH | BPF_K, 16);
    EMIT(BPF_ALU | BPF_XOR | BPF_X, 0);
    EMIT(BPF_ALU | BPF_MOD | BPF_K, queue_count);
    JUMP(BPF_JMP | BPF_JEQ | BPF_K, lane_index, 0, 1);
    const unsigned match = at;
    EMIT(BPF_RET | BPF_K, 1);
    const unsigned miss = at;
    EMIT(BPF_RET | BPF_K, 0);
    const unsigned invalid = lane_index == 0 ? match : miss;
#undef EMIT
#undef JUMP
    for (unsigned i = 0; i < invalid_count; ++i)
        program[invalid_jumps[i]].jf = (uint8_t) (invalid - invalid_jumps[i] - 1);
    program[bad_version].jt   = (uint8_t) (invalid - bad_version - 1);
    program[fragment].jt      = (uint8_t) (fallback - fragment - 1);
    program[short_payload].jt = (uint8_t) (fallback - short_payload - 1);
    if (mode != kDeviceOpaqueFlowPrefix)
    {
        program[native].jt = (uint8_t) (prefix - native - 1);
        program[opaque].jf = (uint8_t) ((mode == kDeviceOpaqueFlowPeer ? fallback : miss) - opaque - 1);
    }
    assert(at == (mode == kDeviceOpaqueFlowPrefix ? 61U : 64U));
    size_t used = (size_t) snprintf(output, kCaptureLinuxSteeringFilterSize, "%u", at);
    for (unsigned i = 0; i < at; ++i)
    {
        const int written = snprintf(output + used,
                                     kCaptureLinuxSteeringFilterSize - used,
                                     ",%u %u %u %u",
                                     program[i].code,
                                     program[i].jt,
                                     program[i].jf,
                                     program[i].k);
        assert(written > 0 && (size_t) written < kCaptureLinuxSteeringFilterSize - used);
        used += (size_t) written;
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
