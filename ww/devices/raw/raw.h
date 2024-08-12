#pragma once
#include "buffer_pool.h"
#include "hloop.h"
#include "hplatform.h"
#include "hthread.h"
#include "master_pool.h"
#include <stdint.h>

struct raw_device_s;

typedef void (*RawReadEventHandle)(struct raw_device_s *rdev, void *userdata, shift_buffer_t *buf, tid_t tid);

typedef struct raw_device_s
{
    char     *name;
    int       socket;
    uint32_t  mark;
    void     *userdata;
    hthread_t read_thread;
    hthread_t write_thread;

    hthread_routine routine_reader;
    hthread_routine routine_writer;

    master_pool_t     *reader_message_pool;
    generic_pool_t    *reader_shift_buffer_pool;
    buffer_pool_t     *reader_buffer_pool;
    RawReadEventHandle read_event_callback;

    struct hchan_s *writer_buffer_channel;
    atomic_bool     running;
    atomic_bool     up;

} raw_device_t;

bool bringRawDeviceUP(raw_device_t *rdev);
bool bringRawDeviceDown(raw_device_t *rdev);

raw_device_t *createRawDevice(const char *name, uint32_t mark, void *userdata, RawReadEventHandle cb);

void writeToRawDevce(raw_device_t *rdev, shift_buffer_t *buf);
