#pragma once
#include "hloop.h"
#include "hplatform.h"
#include <stdint.h>

typedef union {
    int   fd;     // Unix file descriptor
    void *handle; // Windows handle (void* can hold HANDLE)
} tun_handle_t;

typedef struct tun_device_s
{
    char        *name;
    hio_t       *io;
    tun_handle_t handle;

} tun_device_t;

tun_device_t *createTunDevice(hloop_t *loop, const char *name, bool offload);
