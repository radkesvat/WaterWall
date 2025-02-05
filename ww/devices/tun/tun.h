#pragma once
#include "wlibc.h"
#include "buffer_pool.h"
#include "wloop.h"
#include "wplatform.h"
#include "wthread.h"
#include "master_pool.h"
#include "worker.h"

#define TUN_LOG_EVERYTHING false

#ifdef OS_UNIX
typedef int tun_handle_t;
#else
typedef void *tun_handle_t; // Windows handle (void* can hold HANDLE)
#endif

struct tun_device_s;

typedef void (*TunReadEventHandle)(struct tun_device_s *tdev, void *userdata, sbuf_t *buf, wid_t tid);

typedef struct tun_device_s {
    char *name;
    tun_handle_t handle;
    void        *userdata;
    wthread_t    read_thread;
    wthread_t    write_thread;

    wthread_routine routine_reader;
    wthread_routine routine_writer;

    master_pool_t     *reader_message_pool;
    buffer_pool_t     *reader_buffer_pool;
    buffer_pool_t     *writer_buffer_pool;
    
    TunReadEventHandle read_event_callback;

    struct wchan_s *writer_buffer_channel;
    atomic_bool     running;
    atomic_bool     up;

} tun_device_t;

// Function prototypes
tun_device_t *tundeviceCreate(const char *name, bool offload, void *userdata, TunReadEventHandle cb);
bool tundeviceBringUp(tun_device_t *tdev);
bool tundeviceBringDown(tun_device_t *tdev);
bool tundeviceAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet);
bool tundeviceUnAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet);
bool tundeviceWrite(tun_device_t *tdev, sbuf_t *buf);
