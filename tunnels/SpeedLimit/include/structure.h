#pragma once

#include "wwapi.h"

typedef struct speedlimit_bucket_s
{
    uint64_t tokens_units;
    uint64_t last_refill_ms;
} speedlimit_bucket_t;

typedef struct speedlimit_atomic_bucket_s
{
    atomic_ullong tokens_units;
    atomic_ullong last_refill_ms;
} speedlimit_atomic_bucket_t;

typedef struct speedlimit_tstate_s
{
    uint64_t bytes_per_sec;
    uint64_t bucket_capacity_units;
    uint64_t refill_units_per_step;
    uint32_t recharge_interval_ms;
    uint8_t  limit_mode;
    uint8_t  work_mode;
    uint16_t _padding0;

    speedlimit_atomic_bucket_t global_bucket;
    speedlimit_bucket_t        worker_buckets[];
} speedlimit_tstate_t;

typedef struct speedlimit_lstate_s
{
    tunnel_t           *tunnel;
    line_t             *line;
    buffer_queue_t      up_queue;
    buffer_queue_t      down_queue;
    wtimer_t           *up_timer;
    wtimer_t           *down_timer;
    speedlimit_bucket_t line_bucket;
    bool                prev_side_externally_paused;
    bool                next_side_externally_paused;
    bool                prev_side_locally_paused;
    bool                next_side_locally_paused;
} speedlimit_lstate_t;

enum
{
    kTunnelStateSize         = sizeof(speedlimit_tstate_t),
    kLineStateSize           = sizeof(speedlimit_lstate_t),
    kSpeedLimitQueueCap      = 4,
    kSpeedLimitImmediateMs   = 1,
    kSpeedLimitDefaultTickMs = 10,
    kSpeedLimitUnitsPerByte  = 1000
};

enum speedlimit_limit_mode_e
{
    kSpeedLimitLimitModePerLine   = kDvsFirstOption,
    kSpeedLimitLimitModeAllLines  = kDvsSecondOption,
    kSpeedLimitLimitModePerWorker = kDvsThirdOption
};

enum speedlimit_work_mode_e
{
    kSpeedLimitWorkModeDrop  = kDvsFirstOption,
    kSpeedLimitWorkModePause = kDvsSecondOption
};

WW_EXPORT void         speedlimitTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *speedlimitTunnelCreate(node_t *node);
WW_EXPORT api_result_t speedlimitTunnelApi(tunnel_t *instance, sbuf_t *message);

void speedlimitTunnelOnPrepair(tunnel_t *t);
void speedlimitTunnelOnStart(tunnel_t *t);
void speedlimitTunnelOnStop(tunnel_t *t);

void speedlimitTunnelUpStreamInit(tunnel_t *t, line_t *l);
void speedlimitTunnelUpStreamEst(tunnel_t *t, line_t *l);
void speedlimitTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void speedlimitTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void speedlimitTunnelUpStreamPause(tunnel_t *t, line_t *l);
void speedlimitTunnelUpStreamResume(tunnel_t *t, line_t *l);

void speedlimitTunnelDownStreamInit(tunnel_t *t, line_t *l);
void speedlimitTunnelDownStreamEst(tunnel_t *t, line_t *l);
void speedlimitTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void speedlimitTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void speedlimitTunnelDownStreamPause(tunnel_t *t, line_t *l);
void speedlimitTunnelDownStreamResume(tunnel_t *t, line_t *l);

void speedlimitLinestateInitialize(speedlimit_lstate_t *ls, tunnel_t *t, line_t *l);
void speedlimitLinestateDestroy(speedlimit_lstate_t *ls);

uint64_t speedlimitPeekAvailableUnits(tunnel_t *t, line_t *l);
size_t   speedlimitGrantBytes(tunnel_t *t, line_t *l, size_t requested_bytes, bool allow_partial);
uint32_t speedlimitGetRetryDelayMs(tunnel_t *t, line_t *l);
void     speedlimitScheduleUpstreamDrain(speedlimit_lstate_t *ls, uint32_t delay_ms);
void     speedlimitScheduleDownstreamDrain(speedlimit_lstate_t *ls, uint32_t delay_ms);

void speedlimitUpstreamDrainTimerCallback(wtimer_t *timer);
void speedlimitDownstreamDrainTimerCallback(wtimer_t *timer);
