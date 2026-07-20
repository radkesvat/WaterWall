#include "buffer_pool.h"
#include "global_state.h"
#include "master_pool.h"
#include "threadsafe_generic_pool.h"
#include "wevent.h"
#include "wlibc.h"
#include "wloop.h"
#include "wsocket.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct udp_test_state_s
{
    buffer_pool_t *pool;
    uint32_t       lengths[2];
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

    require(state->callback_count < ARRAY_SIZE(state->lengths), "received too many UDP callbacks");
    state->lengths[state->callback_count++] = sbufGetLength(buf);
    bufferpoolReuseBuffer(state->pool, buf);
}

static void sendDatagram(int sender, sockaddr_u *target, const void *payload, size_t payload_len)
{
    int sent = sendto(sender,
                      (const char *) payload,
                      payload_len,
                      0,
                      &target->sa,
                      sockaddrLen(target));
    require(sent == (int) payload_len, "failed to send UDP test datagram");
}

int main(void)
{
    master_pool_t *large_master = masterpoolCreateWithCapacity(8);
    master_pool_t *small_master = masterpoolCreateWithCapacity(8);
    master_pool_t *wio_master   = masterpoolCreateWithCapacity(8);
    buffer_pool_t *buffer_pool  = bufferpoolCreate(large_master, small_master, 8, 8192, 1024);
    threadsafe_generic_pool_t *wio_pool =
        threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(wio_master, sizeof(wio_t), 8);
    threadsafe_generic_pool_t *wio_pools[] = {wio_pool};

    GSTATE.shortcut_wios_pools = wio_pools;
    tl_wid                     = 0;

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
    require(getsockname(wioGetFD(server), &target.sa, &target_len) == 0,
            "failed to obtain UDP test server address");
    require(sockaddrPort(&target) != 0, "UDP test server did not receive an ephemeral port");

    int sender = (int) socket(AF_INET, SOCK_DGRAM, 0);
    require(sender >= 0, "failed to create UDP test sender");

    const char placeholder = 0;
    sendDatagram(sender, &target, &placeholder, 0);
    require(wloopRun(loop) == 0, "UDP event loop failed while receiving empty datagram");
    require(state.callback_count == 1, "empty UDP datagram was not delivered");
    require(state.lengths[0] == 0, "empty UDP datagram was delivered with a nonzero length");
    require(wioIsOpened(server), "empty UDP datagram closed the receiving socket");

    const char payload = 'x';
    sendDatagram(sender, &target, &payload, sizeof(payload));
    require(wloopRun(loop) == 0, "UDP event loop failed after receiving empty datagram");
    require(state.callback_count == 2, "UDP receive did not continue after empty datagram");
    require(state.lengths[1] == sizeof(payload), "follow-up UDP datagram had the wrong length");

    closesocket(sender);
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
