#pragma once

#include "capture.h"

#include "buffer_pool.h"
#include "devices/capture/capture_lifecycle.h"
#include "devices/device_reader_session.h"
#include "loggers/log_rate_limiter.h"
#include "wmutex.h"
#include "wthread.h"

#if defined(OS_LINUX)
typedef enum capture_rule_state_e
{
    kCaptureRuleAbsent = 0,
    kCaptureRuleInstalled,
    kCaptureRuleOutcomeUnknown
} capture_rule_state_t;

typedef struct capture_range_rule_states_s
{
    capture_rule_state_t queue;
    capture_rule_state_t notrack;
} capture_range_rule_states_t;
#endif

struct capture_device_s
{
    char *name;
#ifdef OS_WIN
    HANDLE handle;
    char  *filter;
    bool   reader_exit_confirmed;

#else
    /* The lifecycle coordinator owns native queues until worker activation and
     * after owner quiescence. No external Linux reader thread exists. */
    struct capture_reader_generation_s *reader;
    atomic_uintptr_t                    reader_notify;
    uint16_t                            queue_count;
    struct capture_linux_queue_s       *queues;
    char                              **capture_cidrs;
    uint32_t                            capture_range_count;
    bool                                bypass_conntrack;
    bool                                multi_queue;
    bool                                kernel_queue_tune;
    uint32_t                            kernel_queue_packets;
    uint32_t                            kernel_receive_buffer;
    uint32_t                            kernel_queue_profile;
    bool                                skip_sysctl;
    char                                protocol_filter[kCaptureLinuxProtocolFilterSize];
    capture_range_rule_states_t        *rule_states;
    uint64_t                            rule_token;
    bool                                queue_restartable;
    atomic_bool                         capture_active;
#endif
    bool  drop_captured_packet;
    void *userdata;
#ifdef OS_WIN
    wthread_t       read_thread;
    wthread_routine routine_reader;
#endif

    device_reader_session_t *reader_session;
    buffer_pool_t           *reader_buffer_pool;

    CaptureReadEventHandle read_event_callback;

    atomic_int lifecycle;
#ifdef OS_WIN
    atomic_bool running;
#endif
    atomic_bool up;
};
