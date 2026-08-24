#pragma once

/*
 * Deterministic fallback-branch fixture shared by the three Layer-4 server
 * lifecycle tests.  It models the delayed line-task reference without letting
 * wall-clock time or a real event loop decide when the branch is driven.
 */

#include "tunnel_line_failure_harness.h"

typedef struct fallback_finish_fixture_s fallback_finish_fixture_t;
typedef void (*fallback_finish_inject_fn)(fallback_finish_fixture_t *fixture, line_t *line);
typedef void (*fallback_finish_zero_state_fn)(fallback_finish_fixture_t *fixture, line_t *line);

enum
{
    kFallbackFinishCaptureSpan = 32
};

struct fallback_finish_fixture_s
{
    tunnel_t                     *node;
    tunnel_t                     *fallback;
    fallback_finish_inject_fn     inject_during_payload;
    fallback_finish_zero_state_fn require_node_state_zero;
    uint8_t                       received[256];
    uint32_t                      received_len;
    uint64_t                      received_total_len;
    uint8_t                       received_prefix[kFallbackFinishCaptureSpan];
    uint32_t                      received_prefix_len;
    uint8_t                       received_suffix[kFallbackFinishCaptureSpan];
    uint32_t                      received_suffix_len;
    uint32_t                      init_calls;
    uint32_t                      payload_calls;
    uint32_t                      finish_calls;
};

typedef struct fallback_finish_scheduled_task_s
{
    line_t         *line;
    tunnel_t       *tunnel;
    LineTaskFnNoBuf callback;
    uint32_t        delay_ms;
    bool            pending;
    bool            refuse;
} fallback_finish_scheduled_task_t;

static fallback_finish_scheduled_task_t g_fallback_finish_task;

static fallback_finish_fixture_t *fallbackFinishFixture(tunnel_t *t)
{
    return *(fallback_finish_fixture_t **) tunnelGetState(t);
}

static void fallbackFinishFallbackInit(tunnel_t *t, line_t *line)
{
    discard line;
    ++fallbackFinishFixture(t)->init_calls;
}

static void fallbackFinishCapturePayload(fallback_finish_fixture_t *fixture, const sbuf_t *buf)
{
    const uint8_t *data           = sbufGetRawPtr(buf);
    const uint32_t len            = sbufGetLength(buf);
    const uint32_t received_space = (uint32_t) sizeof(fixture->received) - fixture->received_len;
    const uint32_t received_copy  = min(received_space, len);
    const uint32_t prefix_space   = kFallbackFinishCaptureSpan - fixture->received_prefix_len;
    const uint32_t prefix_copy    = min(prefix_space, len);

    if (received_copy > 0)
    {
        memoryCopy(fixture->received + fixture->received_len, data, received_copy);
        fixture->received_len += received_copy;
    }
    if (prefix_copy > 0)
    {
        memoryCopy(fixture->received_prefix + fixture->received_prefix_len, data, prefix_copy);
        fixture->received_prefix_len += prefix_copy;
    }

    if (len >= kFallbackFinishCaptureSpan)
    {
        memoryCopy(fixture->received_suffix, data + len - kFallbackFinishCaptureSpan, kFallbackFinishCaptureSpan);
        fixture->received_suffix_len = kFallbackFinishCaptureSpan;
    }
    else if (fixture->received_suffix_len + len <= kFallbackFinishCaptureSpan)
    {
        memoryCopy(fixture->received_suffix + fixture->received_suffix_len, data, len);
        fixture->received_suffix_len += len;
    }
    else
    {
        const uint32_t keep = kFallbackFinishCaptureSpan - len;
        memoryMove(fixture->received_suffix, fixture->received_suffix + fixture->received_suffix_len - keep, keep);
        memoryCopy(fixture->received_suffix + keep, data, len);
        fixture->received_suffix_len = kFallbackFinishCaptureSpan;
    }

    fixture->received_total_len += len;
}

static void fallbackFinishFallbackPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    fallback_finish_fixture_t *fixture = fallbackFinishFixture(t);

    fallbackFinishCapturePayload(fixture, buf);
    ++fixture->payload_calls;

    if (fixture->inject_during_payload != NULL)
    {
        fixture->inject_during_payload(fixture, line);
    }

    lineReuseBuffer(line, buf);
}

static void fallbackFinishFallbackFinish(tunnel_t *t, line_t *line)
{
    fallback_finish_fixture_t *fixture = fallbackFinishFixture(t);

    ++fixture->finish_calls;
    if (fixture->require_node_state_zero != NULL)
    {
        fixture->require_node_state_zero(fixture, line);
    }
}

static tunnel_t *fallbackFinishCreateBranch(fallback_finish_fixture_t *fixture)
{
    tunnel_t *fallback = tunnelCreate(NULL, sizeof(fallback_finish_fixture_t *), 0);
    twfRequire(fallback != NULL, "failed to create the fallback test branch");

    *(fallback_finish_fixture_t **) tunnelGetState(fallback) = fixture;
    fallback->fnInitU                                        = fallbackFinishFallbackInit;
    fallback->fnPayloadU                                     = fallbackFinishFallbackPayload;
    fallback->fnFinU                                         = fallbackFinishFallbackFinish;
    fixture->fallback                                        = fallback;
    return fallback;
}

static sbuf_t *fallbackFinishMakePayload(buffer_pool_t *pool, const char *text)
{
    const uint32_t len = (uint32_t) stringLength(text);
    sbuf_t        *buf = bufferpoolGetLargeBuffer(pool);

    twfRequire(sbufGetMaximumWriteableSize(buf) >= len, "test payload exceeded the pooled buffer");
    sbufSetLength(buf, len);
    sbufWrite(buf, text, len);
    return buf;
}

static void fallbackFinishResetScheduledTask(void)
{
    twfRequire(! g_fallback_finish_task.pending, "the preceding test retained a delayed task");
    memoryZero(&g_fallback_finish_task, sizeof(g_fallback_finish_task));
}

bool __wrap_lineScheduleDelayedTask(line_t *const line, LineTaskFnNoBuf callback, uint32_t delay_ms, tunnel_t *t);

bool __wrap_lineScheduleDelayedTask(line_t *const line, LineTaskFnNoBuf callback, uint32_t delay_ms, tunnel_t *t)
{
    twfRequire(! g_fallback_finish_task.pending, "more than one delayed fallback task was scheduled");

    if (g_fallback_finish_task.refuse)
    {
        return false;
    }

    lineLock(line);
    g_fallback_finish_task = (fallback_finish_scheduled_task_t) {
        .line     = line,
        .tunnel   = t,
        .callback = callback,
        .delay_ms = delay_ms,
        .pending  = true,
        .refuse   = false,
    };
    return true;
}

static void fallbackFinishDriveDelayedTask(void)
{
    twfRequire(g_fallback_finish_task.pending, "the test expected a delayed fallback task");

    const fallback_finish_scheduled_task_t task = g_fallback_finish_task;
    memoryZero(&g_fallback_finish_task, sizeof(g_fallback_finish_task));

    if (lineIsAlive(task.line))
    {
        task.callback(task.tunnel, task.line);
    }
    lineUnlock(task.line);
}
