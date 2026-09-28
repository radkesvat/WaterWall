#pragma once

/* Writer-private scatter/gather record. It borrows unchanged packet buffers
 * until the complete write attempt (including EINTR retries) has finished. */
#include "devices/tun/tun.h"
#include "shiftbuffer.h"
#include <sys/uio.h>

enum
{
    kTunWriteBatchPackets      = 64,
    kTunWriteBatchCharge       = 256 * 1024,
    kTunWriteGsoHeaderCapacity = 20 + 60
};

typedef struct tun_linux_gso_write_s
{
    uint8_t      metadata[kTunVirtioHeaderSize];
    uint8_t      header[kTunWriteGsoHeaderCapacity];
    struct iovec iov[kTunWriteBatchPackets + 2];
    size_t       length;
    unsigned     count;
} tun_linux_gso_write_t;

/* Returns the compatible prefix length, or one for ordinary handling. Only
 * call with a nonempty bounded batch on an active trusted, virtio-framed pair.
 * A result >= 2 initializes record; it never allocates or mutates an input. */
unsigned tunLinuxGsoBuildWrite(sbuf_t *const *packets, unsigned count, uint16_t mtu, tun_linux_gso_write_t *record);
