#pragma once
#include "buffer_pool.h"
#include "hloop.h"
#include "wplatform.h"
#include "wthread.h"
#include "master_pool.h"
#include <stdint.h>

struct capture_device_s;

typedef void (*CaptureReadEventHandle)(struct capture_device_s *cdev, void *userdata, shift_buffer_t *buf, tid_t tid);

typedef struct capture_device_s
{
    char     *name;
    int       socket;
    uint32_t  queue_number;
    bool      drop_captured_packet;
    void     *userdata;
    wthread_t read_thread;
    wthread_t write_thread;

    wthread_routine routine_reader;
    wthread_routine routine_writer;

    master_pool_t  *reader_message_pool;
    buffer_pool_t  *reader_buffer_pool;
    buffer_pool_t  *writer_buffer_pool;

    CaptureReadEventHandle read_event_callback;

    struct wchan_s *writer_buffer_channel;
    atomic_bool     running;
    atomic_bool     up;

} capture_device_t;

bool bringCaptureDeviceUP(capture_device_t *cdev);
bool bringCaptureDeviceDown(capture_device_t *cdev);

capture_device_t *createCaptureDevice(const char *name, uint32_t queue_number, void *userdata,
                                      CaptureReadEventHandle cb);
bool              writeToCaptureDevce(capture_device_t *cdev, shift_buffer_t *buf);
