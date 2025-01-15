#pragma once
#include "buffer_pool.h"
#include "wloop.h"
#include "wplatform.h"
#include "wthread.h"
#include "master_pool.h"
#include <stdint.h>

struct raw_device_s;

typedef void (*RawReadEventHandle)(struct raw_device_s *rdev, void *userdata, sbuf_t *buf, tid_t tid);

typedef struct raw_device_s
{
    char     *name;
    int       socket;
    uint32_t  mark;
    void     *userdata;
    wthread_t read_thread;
    wthread_t write_thread;

    wthread_routine routine_reader;
    wthread_routine routine_writer;

    master_pool_t  *reader_message_pool;
    buffer_pool_t  *reader_buffer_pool;
    buffer_pool_t  *writer_buffer_pool;

    RawReadEventHandle read_event_callback;

    struct wchan_s *writer_buffer_channel;
    atomic_bool     running;
    atomic_bool     up;

} raw_device_t;

bool bringRawDeviceUP(raw_device_t *rdev);
bool bringRawDeviceDown(raw_device_t *rdev);

raw_device_t *createRawDevice(const char *name, uint32_t mark, void *userdata, RawReadEventHandle cb);

bool writeToRawDevce(raw_device_t *rdev, sbuf_t *buf);
