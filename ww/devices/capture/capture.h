#pragma once

#include "wlibc.h"

#include "buffer_pool.h"
#include "devices/capture/capture_lifecycle.h"
#include "devices/device_reader_session.h"
#include "loggers/log_rate_limiter.h"
#include "wmutex.h"
#include "worker.h"
#include "wthread.h"

struct capture_device_s;

typedef void (*CaptureReadEventHandle)(struct capture_device_s *cdev, void *userdata, sbuf_t *buf, wid_t tid);

#if defined(OS_LINUX)
typedef enum capture_rule_state_e
{
    kCaptureRuleAbsent = 0,
    kCaptureRuleInstalled,
    kCaptureRuleOutcomeUnknown
} capture_rule_state_t;
#endif

typedef struct capture_device_s
{
    char *name;
#ifdef OS_WIN
    HANDLE handle;
    char  *filter;
    bool   reader_exit_confirmed;

#else
    int      socket;
    int      linux_pipe_fds[2]; // used for signaling read thread to stop
    uint32_t queue_number;
    char   **capture_cidrs;
    uint32_t capture_range_count;
    // Serialized Linux rule/resource state, independent of `up`. Each CIDR rule
    // is tracked explicitly because a timed-out iptables mutation may have
    // committed before its command was terminated.
    capture_rule_state_t *rule_states;
    uint64_t              rule_token;
    // Cleared when a terminal lifecycle failure closes the NFQUEUE socket.
    // Such an object may retry rule cleanup, but must never bind or start again.
    bool queue_restartable;
    // Reader state and queue-socket ownership are synchronized by this mutex.
    // A successfully created thread remains joinable even after it exits.
    pthread_mutex_t reader_state_mutex;
    pthread_cond_t  reader_state_changed;
    bool            reader_thread_joinable;
    bool            reader_ready;
    bool            reader_failed;
    bool            reader_stop_requested;
    // Set by terminal lifecycle cleanup while a reader owns `socket`. The
    // reader wrapper closes it only after the routine has stopped using its
    // copied descriptor.
    bool               close_queue_on_reader_exit;
    atomic_bool        capture_active;
    int                netfilter_queue_number;
    log_rate_limiter_t netfilter_discard_log_limiter;
#endif
    bool      drop_captured_packet;
    void     *userdata;
    wthread_t read_thread;

    wthread_routine routine_reader;

    device_reader_session_t *reader_session;
    buffer_pool_t           *reader_buffer_pool;

    CaptureReadEventHandle read_event_callback;

    atomic_int  lifecycle;
    atomic_bool running;
    atomic_bool up;

} capture_device_t;

bool caputredeviceBringUp(capture_device_t *cdev);
bool caputredeviceBringDown(capture_device_t *cdev);

capture_device_t *caputredeviceCreate(const char *name, const ipmask_t *capture_ranges, uint32_t capture_range_count,
                                      void *userdata, CaptureReadEventHandle cb);

void capturedeviceDestroy(capture_device_t *cdev);
