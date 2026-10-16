#pragma once

#include "raw.h"
#include "raw_lifecycle.h"
#include "raw_writer.h"

typedef struct raw_native_writer_s raw_native_writer_t;

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
    /* Lifecycle-owner state; immutable while output is admitted. */
    bool bypass_conntrack;
    bool notrack_rule_pending;
    char notrack_comment[48];
#endif
    uint32_t             mark;
    void                *userdata;
    atomic_int           lifecycle;
    raw_writer_t         writer;
    size_t               writer_worker_count;
    raw_native_writer_t *writer_states;
};
