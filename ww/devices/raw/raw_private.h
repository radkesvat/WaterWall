#pragma once

#include "raw.h"

#include "buffer_pool.h"
#include "devices/device_writer_channel.h"
#include "loggers/log_rate_limiter.h"
#include "raw_lifecycle.h"
#include "wthread.h"

enum
{
    kRawDiscardReportIntervalMs = 1000
};

struct raw_device_s
{
    char *name;
#ifdef OS_WIN
    HANDLE handle;
#else
    int socket;
#endif
#ifdef OS_LINUX
    /* Lifecycle-owner state; never modified by the writer thread. */
    bool bypass_conntrack;
    bool notrack_rule_pending;
    char notrack_comment[48];
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
};
