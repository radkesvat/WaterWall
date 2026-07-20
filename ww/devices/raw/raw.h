#pragma once

#include "wlibc.h"

#include "buffer_pool.h"
#include "wthread.h"

struct raw_device_s;

typedef struct raw_device_s
{
    char *name;
#ifdef OS_WIN
    HANDLE handle;
#else
    int                socket;
    uint64_t           discarded_packet_total;
    uint64_t           discarded_packet_suppressed;
    uint64_t           oversized_packet_total;
    uint64_t           message_too_large_packet_total;
    unsigned long long discard_last_report_ms;
#endif
    uint32_t  mark;
    void     *userdata;
    wthread_t read_thread;
    wthread_t write_thread;

    wthread_routine routine_writer;

    buffer_pool_t  *writer_buffer_pool;
    struct wchan_s *writer_buffer_channel;
    atomic_bool     running;
    atomic_bool     up;

} raw_device_t;

bool rawdeviceBringUp(raw_device_t *rdev);
bool rawdeviceBringDown(raw_device_t *rdev);
bool rawdeviceWrite(raw_device_t *rdev, sbuf_t *buf);

raw_device_t *rawdeviceCreate(const char *name, uint32_t mark, void *userdata);

void rawdeviceDestroy(raw_device_t *rdev);
