#include "wlibc.h"


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

static void testHtonll64(void)
{
    static const uint8_t network_order[8] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    const uint64_t host_value = UINT64_C(0x0102030405060708);

    // 1. htonll() must serialize to the network (big-endian) byte sequence
    //    regardless of the host byte order.
    uint64_t converted = htonll(host_value);
    uint8_t  converted_bytes[8];
    memoryCopy(converted_bytes, &converted, sizeof(converted));
    require(memoryEqual(converted_bytes, network_order, sizeof(network_order)),
            "htonll produced the wrong network byte order");

    // 2. ntohll() must decode a known network-order byte sequence back to the
    //    host value. The byte checks are required because a round trip alone can
    //    pass when both functions share the same wrong transformation.
    uint64_t loaded;
    memoryCopy(&loaded, network_order, sizeof(loaded));
    require(ntohll(loaded) == host_value, "ntohll did not decode the network byte order");

    // 3. Round-trip identity across a value with every byte distinct.
    const uint64_t round_trip = UINT64_C(0xdeadbeefcafef00d);
    require(ntohll(htonll(round_trip)) == round_trip, "ntohll(htonll(x)) was not the identity");
    require(htonll(ntohll(round_trip)) == round_trip, "htonll(ntohll(x)) was not the identity");

    // 4. GET_BE64/PUT_BE64 must agree with the same network byte order.
    uint8_t stored[8];
    PUT_BE64(stored, host_value);
    require(memoryEqual(stored, network_order, sizeof(network_order)), "PUT_BE64 stored the wrong byte order");
    require(GET_BE64(network_order) == host_value, "GET_BE64 decoded the wrong value");
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
    testHtonll64();
    testBigEndianUnalignedAccess();
    testLittleEndianUnalignedAccess();
    return 0;
}
