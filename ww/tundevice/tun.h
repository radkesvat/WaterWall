#pragma once
#include "hloop.h"
#include "hplatform.h"
#include "hthread.h"
#include <stdint.h>

#ifdef OS_UNIX
typedef int tun_handle_t;
#else
typedef void *tun_handle_t; // Windows handle (void* can hold HANDLE)
#endif

typedef struct tun_device_s
{
    char        *name;
    // hio_t       *io; not using fd multiplexer
    tun_handle_t handle;
    hthread_t    readThread;
    hthread_t    writeThread;
    atomic_bool stop;
    atomic_bool up;


} tun_device_t;

tun_device_t *createTunDevice(const char *name, bool offload);
