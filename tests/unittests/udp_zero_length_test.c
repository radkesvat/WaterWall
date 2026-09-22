#include "wevent.h"
#include "wwapi.h"

#include "threadsafe_generic_pool.h"
#include "wlibc.h"
#include "worker_registry_fixture.h"
#include "wsocket.h"

#ifdef WW_UDP_READ_IOCTL_TEST
#include <stdarg.h>
#include <sys/ioctl.h>

static int          query_fd = -1;
static int          query_error;
static int          query_override = -1;
static unsigned int query_calls;
int                 __real_ioctl(int fd, unsigned long request, ...);
int                 __wrap_ioctl(int fd, unsigned long request, ...);

int __wrap_ioctl(int fd, unsigned long request, ...)
{
    va_list args;
    va_start(args, request);
    void *arg = va_arg(args, void *);
    va_end(args);
    if (fd == query_fd && request == FIONREAD)
    {
        ++query_calls;
        if (query_error != 0)
        {
            errno = query_error;
            return -1;
        }
        if (query_override >= 0)
        {
            *(int *) arg = query_override;
            return 0;
        }
    }
    return __real_ioctl(fd, request, arg);
}
#endif

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

typedef struct udp_test_state_s
{
    buffer_pool_t *pool;
    struct
    {
        uint32_t length;
        uint32_t capacity;
    } expected[16];
    uint32_t       expected_count;
    uint32_t       callback_count;
} udp_test_state_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void onUdpRead(wio_t *io, sbuf_t *buf)
{
    udp_test_state_t *state = weventGetUserdata(io);

    require(state->callback_count < state->expected_count, "received too many UDP callbacks");
    const uint32_t index = state->callback_count++;
    require(sbufGetLength(buf) == state->expected[index].length, "UDP datagram was truncated or combined");
    require(sbufGetTotalCapacityNoPadding(buf) == state->expected[index].capacity,
            "UDP read selected the wrong buffer tier");
    require(buf->flags == 0 && sbufGetLeftCapacity(buf) >= bufferpoolGetLargeBufferPadding(state->pool),
            "UDP read lost its ordinary representation or required padding");
    const uint8_t *payload = sbufGetRawPtr(buf);
    for (uint32_t i = 0; i < sbufGetLength(buf); ++i)
        require(payload[i] == 0x5A, "UDP payload was corrupted");
    bufferpoolReuseBuffer(state->pool, buf);
}

static void sendDatagram(int sender, sockaddr_u *target, const void *payload, size_t payload_len)
{
    int sent = sendto(sender, (const char *) payload, payload_len, 0, &target->sa, sockaddrLen(target));
    require(sent == (int) payload_len, "failed to send UDP test datagram");
}

static void queueDatagram(udp_test_state_t *state, int sender, sockaddr_u *target, uint32_t length,
                          uint32_t expected_capacity)
{
    uint8_t payload[65507];
    require(length <= sizeof(payload) && state->expected_count < ARRAY_SIZE(state->expected),
            "UDP fixture exceeded its bounds");
    memset(payload, 0x5A, length);
    state->expected[state->expected_count].length     = length;
    state->expected[state->expected_count++].capacity = expected_capacity;
    sendDatagram(sender, target, payload, length);
}

static void receiveQueued(wloop_t *loop, udp_test_state_t *state)
{
    while (state->callback_count < state->expected_count)
        require(wloopRun(loop) == 0, "UDP event loop failed while receiving queued datagrams");
}

int main(void)
{
    master_pool_t             *large_master = masterpoolCreateWithCapacity(8);
    master_pool_t             *small_master = masterpoolCreateWithCapacity(8);
    master_pool_t             *medium_master = masterpoolCreateWithCapacity(8);
    master_pool_t             *splice_master = masterpoolCreateWithCapacity(8);
    master_pool_t             *wio_master   = masterpoolCreateWithCapacity(8);
    buffer_pool_t             *buffer_pool   = bufferpoolCreate(large_master,
                                                  medium_master,
                                                  small_master,
                                                  splice_master,
                                                  8,
                                                  8192,
                                                  MEDIUM_BUFFER_SIZE_RAM_HIGH,
                                                  512,
                                                  8192,
                                                  8192);
    bufferpoolUpdateAllocationPaddings(buffer_pool, 64, 64, 64, 64);
    threadsafe_generic_pool_t *wio_pool =
        threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(wio_master, sizeof(wio_t), 8);
    threadsafe_generic_pool_t *wio_pools[] = {wio_pool};

    GSTATE.flag_initialized = true;
    GSTATE.workers_count    = 2;
    testWorkerRegistryInstall(&g_test_worker_registry);
    GSTATE.shortcut_wios_pools = wio_pools;
    testWorkerBindWID(0);

    wloop_t *loop = wloopCreate(WLOOP_FLAG_RUN_ONCE, buffer_pool, 0);
    require(loop != NULL, "failed to create UDP test event loop");

    wio_t *server = wloopCreateUdpServer(loop, "127.0.0.1", 0);
    require(server != NULL, "failed to create UDP test server");

    udp_test_state_t state = {.pool = buffer_pool};
    weventSetUserData(server, &state);
    wioSetCallBackRead(server, onUdpRead);
    require(wioRead(server) == 0, "failed to start UDP test receive");

    sockaddr_u target;
    memoryZero(&target, sizeof(target));
    socklen_t target_len = sizeof(target);
    require(getsockname(wioGetFD(server), &target.sa, &target_len) == 0, "failed to obtain UDP test server address");
    require(sockaddrPort(&target) != 0, "UDP test server did not receive an ephemeral port");

    int sender = (int) socket(AF_INET, SOCK_DGRAM, 0);
    require(sender >= 0, "failed to create UDP test sender");

#ifdef WW_UDP_READ_IOCTL_TEST
    query_fd = wioGetFD(server);
#endif
    queueDatagram(&state, sender, &target, 0, 8192);
    receiveQueued(loop, &state);
    require(state.callback_count == 1, "empty UDP datagram was not delivered");
    require(wioIsOpened(server), "empty UDP datagram closed the receiving socket");

#if defined(OS_LINUX)
    queueDatagram(&state, sender, &target, 1, 512);
#else
    queueDatagram(&state, sender, &target, 1, 8192);
#endif
    receiveQueued(loop, &state);
    require(state.callback_count == 2, "UDP receive did not continue after empty datagram");

#ifdef WW_UDP_READ_IOCTL_TEST
    // Use the next datagram's size, not the combined queued size or the TCP read cap.
    queueDatagram(&state, sender, &target, 1, 512);
    queueDatagram(&state, sender, &target, 8193, MEDIUM_BUFFER_SIZE_RAM_HIGH);
    receiveQueued(loop, &state);
    queueDatagram(&state, sender, &target, 1025, 8192);
    receiveQueued(loop, &state);
    queueDatagram(&state, sender, &target, 65507, MEDIUM_BUFFER_SIZE_RAM_HIGH);
    receiveQueued(loop, &state);
    queueDatagram(&state, sender, &target, 0, 8192);
    queueDatagram(&state, sender, &target, 8193, MEDIUM_BUFFER_SIZE_RAM_HIGH);
    receiveQueued(loop, &state);
    require(query_calls == state.callback_count, "UDP receive did not query once per datagram");

    // Failed/zero hints must still read using the original large-buffer allocation.
    query_error = EIO;
    queueDatagram(&state, sender, &target, 1, 8192);
    receiveQueued(loop, &state);
    query_error    = 0;
    query_override = 0;
    queueDatagram(&state, sender, &target, 1, 8192);
    receiveQueued(loop, &state);
    require(wioIsOpened(server) && wioGetError(server) == 0, "availability hints changed socket error state");

    // Retain the truncation guard even if a size hint is stale or incorrect.
    query_override = 1;
    uint8_t oversized[2048];
    memset(oversized, 0x5A, sizeof(oversized));
    const uint32_t before = state.callback_count;
    sendDatagram(sender, &target, oversized, sizeof(oversized));
    require(wloopRun(loop) == 0 && state.callback_count == before, "truncated datagram reached the callback");
    query_override = -1;
    queueDatagram(&state, sender, &target, 1, 512);
    receiveQueued(loop, &state);
#endif

    closesocket(sender);
    wloopDestroy(&loop);
    GSTATE.shortcut_wios_pools = NULL;

    threadsafegenericpoolDestroy(wio_pool);
    bufferpoolDestroy(buffer_pool);

    masterpoolMakeEmpty(wio_master);
    masterpoolMakeEmpty(large_master);
    masterpoolMakeEmpty(small_master);
    masterpoolMakeEmpty(medium_master);
    masterpoolMakeEmpty(splice_master);
    masterpoolDestroy(wio_master);
    masterpoolDestroy(large_master);
    masterpoolDestroy(small_master);
    masterpoolDestroy(medium_master);
    masterpoolDestroy(splice_master);
    return 0;
}
