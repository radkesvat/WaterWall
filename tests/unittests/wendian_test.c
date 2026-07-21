#include "wlibc.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum
{
    kWireLength = 17,
    kStorageSize = 32,
};

typedef union test_storage_u
{
    uint64_t alignment;
    uint8_t  bytes[kStorageSize];
} test_storage_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void testBigEndianUnalignedAccess(void)
{
    static const uint8_t expected[kWireLength] = {
        0x12, 0x34,
        0x56, 0x78, 0x9A,
        0xBC, 0xDE, 0xF0, 0x12,
        0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12,
    };
    test_storage_t storage = {0};
    uint8_t       *start   = storage.bytes + 1;
    uint8_t       *write   = start;

    PUSH_BE16(write, 0x1234U);
    PUSH_BE24(write, 0x56789AU);
    PUSH_BE32(write, 0xBCDEF012U);
    PUSH_BE64(write, UINT64_C(0x3456789ABCDEF012));

    require((size_t) (write - start) == kWireLength, "big-endian push advanced by the wrong length");
    require(memoryEqual(start, expected, sizeof(expected)), "big-endian unaligned write mismatch");

    const uint8_t *read = start;
    uint16_t       v16;
    uint32_t       v24;
    uint32_t       v32;
    uint64_t       v64;

    POP_BE16(read, v16);
    POP_BE24(read, v24);
    POP_BE32(read, v32);
    POP_BE64(read, v64);

    require((size_t) (read - start) == kWireLength, "big-endian pop advanced by the wrong length");
    require(v16 == 0x1234U, "big-endian unaligned 16-bit read mismatch");
    require(v24 == 0x56789AU, "big-endian unaligned 24-bit read mismatch");
    require(v32 == 0xBCDEF012U, "big-endian unaligned 32-bit read mismatch");
    require(v64 == UINT64_C(0x3456789ABCDEF012), "big-endian unaligned 64-bit read mismatch");
}

static void testLittleEndianUnalignedAccess(void)
{
    static const uint8_t expected[kWireLength] = {
        0x34, 0x12,
        0x9A, 0x78, 0x56,
        0x12, 0xF0, 0xDE, 0xBC,
        0x12, 0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34,
    };
    test_storage_t storage = {0};
    uint8_t       *start   = storage.bytes + 1;
    uint8_t       *write   = start;

    PUSH_LE16(write, 0x1234U);
    PUSH_LE24(write, 0x56789AU);
    PUSH_LE32(write, 0xBCDEF012U);
    PUSH_LE64(write, UINT64_C(0x3456789ABCDEF012));

    require((size_t) (write - start) == kWireLength, "little-endian push advanced by the wrong length");
    require(memoryEqual(start, expected, sizeof(expected)), "little-endian unaligned write mismatch");

    const uint8_t *read = start;
    uint16_t       v16;
    uint32_t       v24;
    uint32_t       v32;
    uint64_t       v64;

    POP_LE16(read, v16);
    POP_LE24(read, v24);
    POP_LE32(read, v32);
    POP_LE64(read, v64);

    require((size_t) (read - start) == kWireLength, "little-endian pop advanced by the wrong length");
    require(v16 == 0x1234U, "little-endian unaligned 16-bit read mismatch");
    require(v24 == 0x56789AU, "little-endian unaligned 24-bit read mismatch");
    require(v32 == 0xBCDEF012U, "little-endian unaligned 32-bit read mismatch");
    require(v64 == UINT64_C(0x3456789ABCDEF012), "little-endian unaligned 64-bit read mismatch");
}

int main(void)
{
    testBigEndianUnalignedAccess();
    testLittleEndianUnalignedAccess();
    return 0;
}
