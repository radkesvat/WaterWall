#include "wsocket.h"
#include "wwapi.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void test_socketToFd(void)
{
#ifdef OS_WIN
    // 1. INVALID_SOCKET returns -1 and preserves last-error
    WSASetLastError(WSAEWOULDBLOCK);
    int fd_invalid = socketToFd(INVALID_SOCKET);
    require(fd_invalid == -1, "socketToFd(INVALID_SOCKET) must return -1");
    require(WSAGetLastError() == WSAEWOULDBLOCK, "socketToFd(INVALID_SOCKET) must preserve last-error");

    // 2. Out-of-range positive SOCKET (> INT_MAX) closes handle and sets WSAEMFILE
    SOCKET fake_large_1 = (SOCKET) 0x80000100ULL;
    int    fd_large_1   = socketToFd(fake_large_1);
    require(fd_large_1 == -1, "socketToFd(0x80000100) must return -1");
    require(WSAGetLastError() == WSAEMFILE, "socketToFd(0x80000100) must set WSAEMFILE");

    SOCKET fake_large_2 = (SOCKET) 0xFFFFFFFEULL;
    int    fd_large_2   = socketToFd(fake_large_2);
    require(fd_large_2 == -1, "socketToFd(0xFFFFFFFE) must return -1");
    require(WSAGetLastError() == WSAEMFILE, "socketToFd(0xFFFFFFFE) must set WSAEMFILE");

#ifdef _WIN64
    SOCKET fake_large_3 = (SOCKET) 0x100000000ULL;
    int    fd_large_3   = socketToFd(fake_large_3);
    require(fd_large_3 == -1, "socketToFd(0x100000000) must return -1");
    require(WSAGetLastError() == WSAEMFILE, "socketToFd(0x100000000) must set WSAEMFILE");
#endif

    // 3. INT_MAX passes through
    SOCKET fake_int_max = (SOCKET) INT_MAX;
    int    fd_int_max   = socketToFd(fake_int_max);
    require(fd_int_max == INT_MAX, "socketToFd(INT_MAX) must return INT_MAX");
#else
    int fd_invalid = socketToFd(-1);
    require(fd_invalid == -1, "socketToFd(-1) must return -1");

    int fd_valid = socketToFd(10);
    require(fd_valid == 10, "socketToFd(10) must return 10");
#endif

    // 4. Real socket
    int real_fd = socketToFd(socket(AF_INET, SOCK_STREAM, 0));
    require(real_fd >= 0, "socketToFd(real_socket) must succeed");
    SAFE_CLOSESOCKET(real_fd);
}

static void test_wio_get_bounds(void)
{
    master_pool_t             *large_master = masterpoolCreateWithCapacity(8);
    master_pool_t             *small_master = masterpoolCreateWithCapacity(8);
    master_pool_t             *wio_master   = masterpoolCreateWithCapacity(8);
    buffer_pool_t             *buffer_pool  = bufferpoolCreate(large_master, small_master, 8, 8192, 1024);
    threadsafe_generic_pool_t *wio_pool =
        threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(wio_master, sizeof(wio_t), 8);
    threadsafe_generic_pool_t *wio_pools[] = {wio_pool};

    GSTATE.shortcut_wios_pools = wio_pools;
    tl_wid                     = 0;

    wloop_t *loop = wloopCreate(WLOOP_FLAG_RUN_ONCE, buffer_pool, 0);
    require(loop != NULL, "wloopCreate failed");

    // Negative fds
    require(wioGet(loop, -1) == NULL, "wioGet(loop, -1) must return NULL");
    require(wioGet(loop, INT_MIN) == NULL, "wioGet(loop, INT_MIN) must return NULL");

    // Fd exceeding WIO_MAX_FD
    require(wioGet(loop, WIO_MAX_FD + 1) == NULL, "wioGet(loop, WIO_MAX_FD + 1) must return NULL");

    // Invalid fds are never array indexes in exported lookup helpers.
    require(! wioExists(loop, -1), "wioExists(loop, -1) must return false");
    require(! wioExists(loop, INT_MIN), "wioExists(loop, INT_MIN) must return false");
    require(! wioExists(loop, WIO_MAX_FD + 1), "wioExists(loop, WIO_MAX_FD + 1) must return false");

    // A rejected attach must leave the detached io untouched and avoid indexing.
    wio_t detached_io = {0};
    detached_io.fd    = -1;
    wioAttach(loop, &detached_io);
    require(detached_io.loop == NULL, "wioAttach must reject negative fds");

    detached_io.fd = WIO_MAX_FD + 1;
    wioAttach(loop, &detached_io);
    require(detached_io.loop == NULL, "wioAttach must reject fds above WIO_MAX_FD");

    // Use a real socket instead of fd 0 so the test does not alter stdin flags.
    int low_fd = socketToFd(socket(AF_INET, SOCK_STREAM, 0));
    require(low_fd >= 0 && low_fd <= WIO_MAX_FD, "test socket fd must be within wio bounds");
    wio_t *io_low = wioGet(loop, low_fd);
    require(io_low != NULL, "wioGet(loop, real_fd) must succeed");

    // WIO_MAX_FD - 1 exercises the upper allocation boundary without making
    // the exact-power-of-two path double the allocation.
    wio_t *io_max = wioGet(loop, WIO_MAX_FD - 1);
    require(io_max != NULL, "wioGet(loop, WIO_MAX_FD - 1) must succeed");

    wloopDestroy(&loop);
    GSTATE.shortcut_wios_pools = NULL;

    threadsafegenericpoolDestroy(wio_pool);
    bufferpoolDestroy(buffer_pool);

    masterpoolMakeEmpty(wio_master);
    masterpoolMakeEmpty(large_master);
    masterpoolMakeEmpty(small_master);
    masterpoolDestroy(wio_master);
    masterpoolDestroy(large_master);
    masterpoolDestroy(small_master);
}

int main(void)
{
#ifdef OS_WIN
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    test_socketToFd();
    test_wio_get_bounds();

#ifdef OS_WIN
    WSACleanup();
#endif

    printf("socket_narrowing_test passed.\n");
    return 0;
}
