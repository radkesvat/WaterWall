#pragma once

#include "wlibc.h"


#include "buffer_pool.h"
#include "master_pool.h"
#include "wloop.h"
#include "worker.h"
#include "wplatform.h"
#include "wthread.h"

#ifdef OS_WIN
#include <iphlpapi.h>
#include <mstcpip.h>
#include <winternl.h>
#include <ws2ipdef.h>

#endif

#define TUN_LOG_EVERYTHING false

struct tun_device_s;

typedef void (*TunReadEventHandle)(struct tun_device_s *tdev, void *userdata, sbuf_t *buf, wid_t tid);

enum
{
    kReadPacketSize                      = 1500,
    kMasterMessagePoosbufGetLeftCapacity = 8,
    kTunWriteChannelQueueMax             = 256,
    kMaxReadQueueSize                    = 100
};

typedef struct tun_device_s
{
#ifdef OS_WIN
    wchar_t                 *name;
    HANDLE                   adapter_handle;
    HANDLE                   session_handle;
    HANDLE                   quit_event;
    MIB_UNICASTIPADDRESS_ROW address_row;
#else
    char *name;
    int   handle;
#endif

    void     *userdata;
    wthread_t read_thread;
    wthread_t write_thread;

    wthread_routine routine_reader;
    wthread_routine routine_writer;

    master_pool_t *reader_message_pool;
    buffer_pool_t *reader_buffer_pool;
    buffer_pool_t *writer_buffer_pool;

    TunReadEventHandle read_event_callback;

    struct wchan_s *writer_buffer_channel;

    atomic_bool running;
    bool        up;

} tun_device_t;

// Function prototypes
tun_device_t *tundeviceCreate(const char *name, bool offload, void *userdata, TunReadEventHandle cb);
void          tundeviceDestroy(tun_device_t *tdev);
bool          tundeviceBringUp(tun_device_t *tdev);
bool          tundeviceBringDown(tun_device_t *tdev);
bool          tundeviceAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet);
bool          tundeviceUnAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet);
bool          tundeviceWrite(tun_device_t *tdev, sbuf_t *buf);
