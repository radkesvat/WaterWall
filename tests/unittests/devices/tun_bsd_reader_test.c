/* Native BSD constructor/reader wiring: control-socket interface flags, real
 * bounded session FIFO, inert TUN syscalls and a stalled worker. Covers creation
 * without interface activation and flag preservation through BringUp/BringDown.
 * No host interface or route is modified.
 * Requires native BSD headers/runtime; defining OS_BSD on Linux is not evidence.
 * CTest: waterwall.tun_bsd_reader_unit */
#include "devices/device_reader_session.h"
#include "fixtures/worker_registry_fixture.h"
#include "test_assert.h"
#include "worker_messages.h"
#include "wwapi.h"
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static unsigned reads, delivered, token_count;
static unsigned mtu_updates, flags_reads, flags_writes, packet_ioctls;
static int      opened_handle;
static short    interface_flags;
static bool     fail_budget, fail_queue;
static struct
{
    WorkerMessageCallback        callback;
    WorkerMessageCleanupCallback cleanup;
    void                        *a, *b, *c;
} tokens[4];

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *a, void *b, void *c);
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *a, void *b, void *c)
{
    require(wid == 0 && token_count < ARRAY_SIZE(tokens), "unexpected BSD worker submission");
    tokens[token_count].callback = callback;
    tokens[token_count].cleanup  = cleanup;
    tokens[token_count].a        = a;
    tokens[token_count].b        = b;
    tokens[token_count++].c      = c;
    return kWorkerMessageSubmitAccepted;
}

static int fixtureOpen(const char *path, int flags, ...)
{
    require(strncmp(path, "/dev/", 5) == 0 && flags == O_RDWR, "unexpected BSD clone open");
    opened_handle = open("/dev/null", flags);
    return opened_handle;
}

static int fixtureIoctl(int fd, unsigned long request, ...)
{
    if (fd == opened_handle)
    {
        ++packet_ioctls;
        errno = ENOTTY;
        return -1;
    }

    int       socket_type;
    socklen_t type_length = sizeof(socket_type);
    require(getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &type_length) == 0 && socket_type == SOCK_DGRAM,
            "BSD interface ioctl did not use a datagram control socket");
    struct sockaddr_in address;
    socklen_t          address_length = sizeof(address);
    require(getsockname(fd, (struct sockaddr *) &address, &address_length) == 0 && address.sin_family == AF_INET,
            "BSD interface ioctl did not use an IPv4 control socket");

    va_list arguments;
    va_start(arguments, request);
    struct ifreq *ifr = va_arg(arguments, struct ifreq *);
    va_end(arguments);
    require(strcmp(ifr->ifr_name, "ww-bsd-fixture") == 0, "BSD interface ioctl used the wrong name");
    switch (request)
    {
    case SIOCSIFMTU:
        require(ifr->ifr_mtu == 1500, "BSD constructor changed its configured MTU");
        ++mtu_updates;
        return 0;
    case SIOCGIFFLAGS:
        ifr->ifr_flags = interface_flags;
        ++flags_reads;
        return 0;
    case SIOCSIFFLAGS:
        interface_flags = ifr->ifr_flags;
        ++flags_writes;
        return 0;
    default:
        errno = ENOTTY;
        return -1;
    }
}

static bool fixtureConfigureBudget(device_reader_session_t *session, size_t charge, uint32_t packets)
{
    return ! fail_budget && deviceReaderSessionConfigureOutputBudget(session, charge, packets);
}

static bool fixtureEnableQueue(device_reader_session_t *session)
{
    return ! fail_queue && deviceReaderSessionEnableWorkerQueue(session);
}

static ssize_t fixtureRead(int fd, void *output, size_t capacity)
{
    discard fd;
    require(capacity == 1501, "BSD reader lost MTU+1 oversized detection");
    uint8_t *packet = output;
    memoryZero(packet, 20);
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = 253;
    PUT_BE16(packet + 2, 20);
    PUT_BE16(packet + 4, reads++);
    PUT_BE32(packet + 12, 0x0a000001);
    PUT_BE32(packet + 16, 0xc0000201);
    uint32_t sum = 0;
    for (unsigned i = 0; i < 20; i += 2)
        sum += GET_BE16(packet + i);
    while (sum >> 16)
        sum = (sum & 65535U) + (sum >> 16);
    PUT_BE16(packet + 10, (uint16_t) ~sum);
    return 20;
}

#define deviceReaderSessionConfigureOutputBudget fixtureConfigureBudget
#define deviceReaderSessionEnableWorkerQueue     fixtureEnableQueue
#define open                                     fixtureOpen
#define ioctl                                    fixtureIoctl
#define read                                     fixtureRead
#include "../../../ww/devices/tun/tun_linux.c"
#include "../../../ww/devices/tun/tun_linux_config.c"
#include "../../../ww/devices/tun/tun_linux_io.c"
#undef open
#undef ioctl
#undef read
#undef deviceReaderSessionConfigureOutputBudget
#undef deviceReaderSessionEnableWorkerQueue

static void receive(tun_device_t *device, void *context, sbuf_t *buffer, wid_t wid)
{
    discard device;
    discard context;
    require(currentThreadOwnsWorker(wid) && wid == 0 &&
                GET_BE16((const uint8_t *) sbufGetRawPtr(buffer) + 4) == delivered++,
            "BSD FIFO changed packet order");
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buffer);
}

static void testInterfaceLifecycle(void)
{
    testCaseSet("BSD interface control socket lifecycle");
    const short original_flags = IFF_POINTOPOINT | IFF_DEBUG;
    interface_flags            = original_flags;
    tun_device_t *device = tundeviceCreate("ww-bsd-fixture", false, false, 1500, NULL, NULL, kDeviceFragmentPreserve);
    require(device != NULL, "BSD constructor failed with unsupported packet-device ioctls rejected");
    require(mtu_updates == 1 && flags_reads == 0 && flags_writes == 0 && packet_ioctls == 0 &&
                interface_flags == original_flags,
            "BSD constructor activated the interface or used a packet descriptor for configuration");
    const int descriptor_flags = fcntl(device->handle, F_GETFL, 0);
    require(descriptor_flags >= 0 && (descriptor_flags & O_NONBLOCK) != 0,
            "BSD constructor published a blocking packet descriptor");

    require(tundeviceBringUp(device) && tundeviceIsUp(device), "BSD BringUp failed");
    require(flags_reads == 1 && flags_writes == 1 && interface_flags == (short) (original_flags | IFF_UP),
            "BSD BringUp did not preserve existing interface flags through the control socket");
    require(! device->reader_joinable, "BSD lifecycle fixture started a reader without a callback");
    require(tundeviceBringDown(device) && tunLifecycleLoad(&device->lifecycle) == kTunLifecycleDown,
            "BSD BringDown failed");
    require(flags_reads == 2 && flags_writes == 2 && interface_flags == original_flags,
            "BSD BringDown changed flags other than IFF_UP");
    tundeviceDestroy(device);
    require(flags_reads == 2 && flags_writes == 2 && packet_ioctls == 0,
            "BSD destruction repeated interface configuration or used the packet descriptor");
}

int main(void)
{
    testCaseSet("native BSD bounded reader wiring");
    require(createInternalLogger(NULL, false) != NULL, "logger setup failed");
    test_worker_registry_t registry = {0};
    GSTATE.workers_count            = 1;
    GSTATE.ram_profile              = 3;
    testWorkerRegistryInstall(&registry);
    testWorkerBindWID(0);
    master_pool_t *large = masterpoolCreateWithCapacity(8), *medium = masterpoolCreateWithCapacity(8);
    master_pool_t *small = masterpoolCreateWithCapacity(8);
    buffer_pool_t *pool  = bufferpoolCreate(large, medium, small, 8, 8192, 32768, 4096, 8192, 8192);
    require(pool != NULL, "worker pool setup failed");
    buffer_pool_t *pools[]                = {pool};
    wloop_t        loop                   = {0};
    wloop_t       *loops[]                = {&loop};
    GSTATE.shortcut_loops                 = loops;
    GSTATE.workers[0].buffer_pool         = pool;
    GSTATE.shortcut_buffer_pools          = pools;
    GSTATE.masterpool_buffer_pools_large  = large;
    GSTATE.masterpool_buffer_pools_medium = medium;
    GSTATE.masterpool_buffer_pools_small  = small;
    testInterfaceLifecycle();
    testCaseSet("native BSD bounded reader wiring");
    for (unsigned failure = 0; failure < 2; ++failure)
    {
        fail_budget = failure == 0;
        fail_queue  = failure == 1;
        require(tundeviceCreate("ww-bsd-fixture", false, false, 1500, NULL, receive, kDeviceFragmentPreserve) == NULL,
                "BSD dispatch setup refusal published a device");
        require(fcntl(opened_handle, F_GETFD) == -1 && errno == EBADF,
                "BSD dispatch setup refusal leaked native handle");
    }
    fail_budget = fail_queue = false;
    tun_device_t *device =
        tundeviceCreate("ww-bsd-fixture", false, false, 1500, NULL, receive, kDeviceFragmentPreserve);
    require(device != NULL, "actual BSD constructor failed");
    device_reader_session_t *session = device->reader_session;
    require(session->output_charge_limit == 8U * 1024U * 1024U && session->output_packet_limit == 1024 &&
                session->worker_queues != NULL,
            "BSD constructor omitted bounded FIFO setup");
    session->output_packet_limit = 2;
    require(deviceReaderSessionBegin(session) != 0, "reader generation did not open");
    testWorkerUnbindWID();
    require(tunDrainPackets(device) == kTunDrainAgain && reads == 3 && token_count == 1 && delivered == 0,
            "BSD drain blocked on the stalled worker or bypassed its FIFO");
    require(atomicLoadRelaxed(&session->output_packets) == 2 &&
                atomic_load_explicit(&session->output_charge, memory_order_relaxed) <= session->output_charge_limit,
            "BSD stalled reader exceeded its retained budget");
    testWorkerBindWID(0);
    tokens[0].callback(getCurrentWorker(), tokens[0].a, tokens[0].b, tokens[0].c);
    require(delivered == 2 && atomicLoadRelaxed(&session->output_packets) == 0, "BSD resume lost accepted input");
    testWorkerUnbindWID();
    require(tunDrainPackets(device) == kTunDrainAgain && token_count == 2, "BSD reader did not recover admission");
    require(tundeviceRequestStop(device), "BSD native stop request failed");
    tokens[1].cleanup(tokens[1].a, tokens[1].b, tokens[1].c, kWorkerMessageCancelTeardown);
    require(delivered == 2 && atomicLoadRelaxed(&session->output_packets) == 0 &&
                atomic_load_explicit(&session->output_charge, memory_order_relaxed) == 0,
            "BSD stop/cancellation retained credits or delivered closed work");
    testWorkerBindWID(0);
    const int handle = device->handle, stop_read = device->linux_pipe_fds[0], stop_write = device->linux_pipe_fds[1];
    tundeviceDestroy(device);
    require(fcntl(handle, F_GETFD) == -1 && fcntl(stop_read, F_GETFD) == -1 && fcntl(stop_write, F_GETFD) == -1,
            "BSD teardown retained native descriptors");
    GSTATE.shortcut_loops        = NULL;
    GSTATE.shortcut_buffer_pools = NULL;
    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large);
    masterpoolMakeEmpty(medium);
    masterpoolMakeEmpty(small);
    masterpoolDestroy(large);
    masterpoolDestroy(medium);
    masterpoolDestroy(small);
    testWorkerRegistryRestore(&registry);
    testWorkerUnbindWID();
    internaloggerDestroy();
    return 0;
}
