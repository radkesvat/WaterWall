#include "buffer_pool.h"
#include "global_state.h"
#include "master_pool.h"
#include "threadsafe_generic_pool.h"
#include "wevent.h"
#include "wloop.h"
#include "wsocket.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>

static int close_callback_count;

int __wrap_connect(int socket_fd, const struct sockaddr *address, socklen_t address_len);

int __wrap_connect(int socket_fd, const struct sockaddr *address, socklen_t address_len)
{
    discard socket_fd;
    discard address;
    discard address_len;

    errno = EINPROGRESS;
    return -1;
}

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static int createHighDescriptor(void)
{
    int socket_fd = (int) socket(AF_INET, SOCK_DGRAM, 0);
    require(socket_fd >= 0, "failed to create test socket");

    int high_fd = fcntl(socket_fd, F_DUPFD, FD_SETSIZE);
    closesocket(socket_fd);
    require(high_fd >= FD_SETSIZE, "failed to duplicate socket beyond FD_SETSIZE");
    return high_fd;
}

static void onClose(wio_t *io)
{
    discard io;
    close_callback_count++;
}

int main(void)
{
    struct rlimit descriptor_limit;
    require(getrlimit(RLIMIT_NOFILE, &descriptor_limit) == 0, "failed to read descriptor limit");
    if (descriptor_limit.rlim_cur <= FD_SETSIZE)
    {
        fprintf(stderr, "SKIP: descriptor limit does not permit an fd beyond FD_SETSIZE\n");
        return 0;
    }

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
    require(loop != NULL, "failed to create select test event loop");

    int    owned_fd = createHighDescriptor();
    wio_t *owned_io = wioGet(loop, owned_fd);
    wioSetCallBackClose(owned_io, onClose);

    require(wioRead(owned_io) == -ERANGE, "owned high descriptor registration did not fail");
    require(wioGetError(owned_io) == ERANGE, "registration error was not recorded on owned io");
    require(close_callback_count == 1, "rejected owned io did not invoke its close callback");
    require(fcntl(owned_fd, F_GETFD) == -1 && errno == EBADF, "rejected owned descriptor remained open");

    int    accept_fd = createHighDescriptor();
    wio_t *accept_io = wioGet(loop, accept_fd);
    wioSetCallBackClose(accept_io, onClose);

    require(wioAccept(accept_io) == -ERANGE, "high listener registration did not fail");
    require(accept_io->accept == 0, "failed listener registration retained accept state");
    require(close_callback_count == 2, "rejected listener did not invoke its close callback");
    require(fcntl(accept_fd, F_GETFD) == -1 && errno == EBADF, "rejected listener descriptor remained open");

    int        connect_fd = createHighDescriptor();
    wio_t     *connect_io = wioGet(loop, connect_fd);
    sockaddr_u peer_addr;
    memoryZero(&peer_addr, sizeof(peer_addr));
    require(sockaddrSetIpAddressPort(&peer_addr, "127.0.0.1", 9) == 0, "failed to prepare connect address");
    wioSetPeerAddr(connect_io, &peer_addr.sa, (int) sockaddrLen(&peer_addr));
    wioSetCallBackClose(connect_io, onClose);

    require(wioConnect(connect_io) == -ERANGE, "high connection registration did not fail");
    require(connect_io->connect == 0, "failed connection registration retained connect state");
    require(connect_io->connect_timer == NULL, "failed connection registration retained its timeout");
    require(close_callback_count == 3, "rejected connection did not invoke its close callback");
    require(fcntl(connect_fd, F_GETFD) == -1 && errno == EBADF, "rejected connection descriptor remained open");

    int    borrowed_fd = createHighDescriptor();
    wio_t *borrowed_io = wioGet(loop, borrowed_fd);

    require(wioAdd(borrowed_io, NULL, WW_READ) == -ERANGE, "borrowed high descriptor registration did not fail");
    require(wioGetError(borrowed_io) == ERANGE, "registration error was not recorded on borrowed io");
    wioReleaseNoClose(borrowed_io);
    require(fcntl(borrowed_fd, F_GETFD) != -1, "borrowed descriptor was closed with its rejected event wrapper");
    closesocket(borrowed_fd);

    int high_level_fd = createHighDescriptor();
    require(wRead(loop, high_level_fd, NULL) == NULL, "high-level read accepted a high descriptor");
    require(fcntl(high_level_fd, F_GETFD) == -1 && errno == EBADF,
            "high-level read did not close its rejected descriptor");

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
    return 0;
}
