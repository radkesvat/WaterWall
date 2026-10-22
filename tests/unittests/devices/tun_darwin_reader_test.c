/* Runs the production Darwin receive drain with finite readv records and a
 * substituted batch sink. Covers exact-MTU input, truncated oversized records,
 * short family prefixes, EINTR/EAGAIN/EOF/EIO, FIFO, padding and buffer ownership.
 * No utun device, native reader thread or host networking is used.
 * Requires native macOS headers/runtime.
 * CTest: waterwall.tun_darwin_reader_unit */
#include "wwapi.h"

#include "devices/device_flow_affinity.h"
#include "test_assert.h"

#include <arpa/inet.h>
#include <sys/uio.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

enum
{
    kFixtureMtu     = 1500,
    kFixturePadding = 64,
    kFixtureFd      = 71,
    kFixtureBurst   = 8
};

typedef struct native_record_s
{
    size_t  wire_length; /* Includes the separate four-byte utun family prefix. */
    int     error;
    uint8_t marker;
} native_record_t;

typedef struct expected_packet_s
{
    uint32_t length;
    uint8_t  marker;
} expected_packet_t;

static const native_record_t   *records;
static const expected_packet_t *expected_packets;
static unsigned                 record_count, reads, expected_count, delivered, checkouts, recycles;
static sbuf_t                  *outstanding[kFixtureBurst];

static sbuf_t *fixtureGetBuffer(buffer_pool_t *pool)
{
    sbuf_t *buffer = bufferpoolGetSmallBuffer(pool);
    for (unsigned i = 0; i < ARRAY_SIZE(outstanding); ++i)
    {
        if (outstanding[i] == NULL)
        {
            outstanding[i] = buffer;
            ++checkouts;
            return buffer;
        }
    }
    require(false, "receive exceeded bounded buffer staging");
    return NULL;
}

static void fixtureReuseBuffer(buffer_pool_t *pool, sbuf_t *buffer)
{
    for (unsigned i = 0; i < ARRAY_SIZE(outstanding); ++i)
    {
        if (outstanding[i] == buffer)
        {
            outstanding[i] = NULL;
            ++recycles;
            bufferpoolReuseBuffer(pool, buffer);
            return;
        }
    }
    require(false, "buffer was returned twice or never checked out");
}

static ssize_t fixtureReadv(int fd, const struct iovec *iov, int count)
{
    require(fd == kFixtureFd && count == 2, "readv selected wrong source or prefix layout");
    require(iov[0].iov_len == sizeof(uint32_t) && iov[1].iov_len == kFixtureMtu + 1U,
            "receive needs one byte beyond MTU to identify truncated oversized records");
    require(((uintptr_t) iov[1].iov_base & 31U) == 0, "family prefix displaced aligned packet storage");
    require(reads < record_count, "receive exceeded the finite native record sequence");
    const native_record_t *record = &records[reads++];
    if (record->error != 0)
    {
        errno = record->error;
        return -1;
    }
    const uint32_t family = htonl(AF_INET);
    const size_t   length = min(record->wire_length, iov[0].iov_len + iov[1].iov_len);
    memcpy(iov[0].iov_base, &family, min(length, iov[0].iov_len));
    if (length > iov[0].iov_len)
        memset(iov[1].iov_base, record->marker, length - iov[0].iov_len);
    return (ssize_t) length;
}

static void fixtureDistribute(device_reader_session_t *session, sbuf_t **buffers, unsigned int count)
{
    for (unsigned i = 0; i < count; ++i)
    {
        require(delivered < expected_count, "unexpected packet escaped receive validation");
        const expected_packet_t *expected = &expected_packets[delivered++];
        const sbuf_t            *buffer   = buffers[i];
        require(sbufGetLength(buffer) == expected->length, "packet boundary or FIFO changed");
        require(sbufGetLeftCapacity(buffer) == kFixturePadding && sbufGetLeftPadding(buffer) == kFixturePadding,
                "utun framing consumed chain padding");
        const uint8_t *bytes = sbufGetRawPtr(buffer);
        require(((uintptr_t) bytes & 31U) == 0, "delivered packet lost pool alignment");
        for (uint32_t offset = 0; offset < expected->length; ++offset)
            require(bytes[offset] == expected->marker, "packet bytes or FIFO changed");
        fixtureReuseBuffer(session->reader_buffer_pool, buffers[i]);
    }
}

#define readv                                       fixtureReadv
#define bufferpoolGetSmallBuffer                    fixtureGetBuffer
#define bufferpoolReuseBuffer                       fixtureReuseBuffer
#define deviceFlowAffinityPostBatchDroppingOverflow fixtureDistribute
#include "../../../ww/devices/tun/tun_darwin.c"
#undef readv
#undef bufferpoolGetSmallBuffer
#undef bufferpoolReuseBuffer
#undef deviceFlowAffinityPostBatchDroppingOverflow

static void runDrainCase(buffer_pool_t *pool, const char *name, const native_record_t *input, unsigned input_count,
                         const expected_packet_t *expected, unsigned output_count, tun_drain_result_t result)
{
    testCaseSet(name);
    records          = input;
    record_count     = input_count;
    expected_packets = expected;
    expected_count   = output_count;
    reads = delivered = checkouts = recycles = 0;
    device_reader_session_t session          = {.reader_buffer_pool = pool};
    tun_device_t            device           = {.name               = "utun-fixture",
                                                .handle             = kFixtureFd,
                                                .reader_session     = &session,
                                                .reader_buffer_pool = pool,
                                                .mtu                = kFixtureMtu};
    require(tunDrainPackets(&device) == result, "receive returned wrong drain result");
    require(reads == input_count && delivered == output_count, "receive lost or repeated input");
    require(checkouts == recycles, "receive retained a checked-out buffer");
    for (unsigned i = 0; i < ARRAY_SIZE(outstanding); ++i)
        require(outstanding[i] == NULL, "receive retained a staged buffer");
}

int main(void)
{
    testCaseSet("tun_darwin_reader_setup");
    require(createInternalLogger(NULL, false) != NULL, "initialize fixture logger");
    master_pool_t *large  = masterpoolCreateWithCapacity(8);
    master_pool_t *medium = masterpoolCreateWithCapacity(8);
    master_pool_t *small  = masterpoolCreateWithCapacity(8);
    require(large != NULL && medium != NULL && small != NULL, "create buffer masters");
    buffer_pool_t *pool = bufferpoolCreate(large, medium, small, 8, 65536, 32768, 4096, 65536, 65536);
    require(pool != NULL, "create reader-owned buffer pool");
    bufferpoolUpdateAllocationPaddings(pool, kFixturePadding, kFixturePadding, kFixturePadding, kFixturePadding);
    GSTATE.ram_profile = kFixtureBurst;

    const native_record_t   bounds[]   = {{4 + kFixtureMtu - 1, 0, 1},
                                          {4 + kFixtureMtu, 0, 2},
                                          {4 + kFixtureMtu + 1, 0, 3},
                                          {4 + kFixtureMtu + 200, 0, 4},
                                          {4 + 32, 0, 5},
                                          {0, EAGAIN, 0}};
    const expected_packet_t accepted[] = {{kFixtureMtu - 1, 1}, {kFixtureMtu, 2}, {32, 5}};
    runDrainCase(pool,
                 "MTU boundaries and truncated record",
                 bounds,
                 ARRAY_SIZE(bounds),
                 accepted,
                 ARRAY_SIZE(accepted),
                 kTunDrainAgain);

    const native_record_t   short_prefix[] = {{3, 0, 1}, {4, 0, 2}, {4 + 32, 0, 5}, {0, EAGAIN, 0}};
    const expected_packet_t ordinary[]     = {{32, 5}};
    runDrainCase(pool, "short utun family prefix", short_prefix, ARRAY_SIZE(short_prefix), ordinary, 1, kTunDrainAgain);

    const native_record_t interrupted[] = {{0, EINTR, 0}, {4 + 32, 0, 5}, {0, EAGAIN, 0}};
    runDrainCase(pool, "interrupted native read", interrupted, ARRAY_SIZE(interrupted), ordinary, 1, kTunDrainAgain);
    const native_record_t failed[] = {{4 + 32, 0, 5}, {0, EIO, 0}};
    runDrainCase(pool, "error flushes accepted batch", failed, ARRAY_SIZE(failed), ordinary, 1, kTunDrainDeviceError);
    const native_record_t eof[] = {{4 + 32, 0, 5}, {0, 0, 0}};
    runDrainCase(pool, "EOF flushes accepted batch", eof, ARRAY_SIZE(eof), ordinary, 1, kTunDrainEndOfStream);

    native_record_t oversized[kFixtureBurst];
    for (unsigned i = 0; i < ARRAY_SIZE(oversized); ++i)
        oversized[i] = (native_record_t) {4 + kFixtureMtu + 1, 0, 0};
    runDrainCase(pool,
                 "oversized records consume bounded read attempts",
                 oversized,
                 ARRAY_SIZE(oversized),
                 NULL,
                 0,
                 kTunDrainAgain);

    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large);
    masterpoolMakeEmpty(medium);
    masterpoolMakeEmpty(small);
    masterpoolDestroy(large);
    masterpoolDestroy(medium);
    masterpoolDestroy(small);
    internaloggerDestroy();
    return 0;
}
