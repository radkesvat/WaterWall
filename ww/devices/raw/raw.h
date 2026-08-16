#pragma once

#include "wlibc.h"

#include "buffer_pool.h"
#include "devices/device_writer_channel.h"
#include "loggers/log_rate_limiter.h"
#include "raw_lifecycle.h"
#include "wthread.h"

struct raw_device_s;

enum
{
    kRawDiscardReportIntervalMs = 1000
};

typedef struct raw_device_s
{
    char *name;
#ifdef OS_WIN
    HANDLE handle;
#else
    int socket;
#endif
    log_rate_limiter_t discard_log_limiter;
    uint64_t           oversized_packet_total;
    uint64_t           message_too_large_packet_total;
    uint64_t           packet_local_send_error_total;
    uint64_t           transient_send_error_total;
    uint32_t           last_discard_error;
    uint32_t           mark;
    void              *userdata;
    wthread_t          read_thread;
    wthread_t          write_thread;

    wthread_routine routine_writer;

    buffer_pool_t          *writer_buffer_pool;
    device_writer_channel_t writer_channel;
    atomic_int              lifecycle;
    bool                    writer_joinable;

} raw_device_t;

bool rawdeviceIsUp(const raw_device_t *rdev);
bool rawdeviceBringUp(raw_device_t *rdev);
void rawdeviceRequestStop(raw_device_t *rdev);
bool rawdeviceBringDown(raw_device_t *rdev);
bool rawdeviceWrite(raw_device_t *rdev, sbuf_t *buf);

raw_device_t *rawdeviceCreate(const char *name, uint32_t mark, void *userdata);

void rawdeviceDestroy(raw_device_t *rdev);
