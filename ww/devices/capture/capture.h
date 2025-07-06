#pragma once

#include "wlibc.h"

#include "buffer_pool.h"
#include "master_pool.h"
#include "wloop.h"
#include "worker.h"
#include "wplatform.h"
#include "wthread.h"

struct capture_device_s;

typedef void (*CaptureReadEventHandle)(struct capture_device_s *cdev, void *userdata, sbuf_t *buf, wid_t tid);

typedef struct capture_device_s
{
    char     *name;
    int       handle;
    int   linux_pipe_fds[2]; // used for signaling read thread to stop

    uint32_t  queue_number;
    bool      drop_captured_packet;
    void     *userdata;
    wthread_t read_thread;

    wthread_routine routine_reader;

    master_pool_t *reader_message_pool;
    buffer_pool_t *reader_buffer_pool;

    CaptureReadEventHandle read_event_callback;

    char           *bringup_command;
    char           *bringdown_command;
    int             netfilter_queue_number;
    
    atomic_int      packets_queued;
    atomic_bool     running;
    atomic_bool     up;

} capture_device_t;

bool caputredeviceBringUp(capture_device_t *cdev);
bool caputredeviceBringDown(capture_device_t *cdev);

capture_device_t *caputredeviceCreate(const char *name, const char *capture_ip, void *userdata,
                                      CaptureReadEventHandle cb);

void capturedeviceDestroy(capture_device_t *cdev);
