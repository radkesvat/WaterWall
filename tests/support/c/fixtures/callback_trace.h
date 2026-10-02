#pragma once

/* Mock next receives upstream, mock prev receives downstream. Finish observation here does not own or destroy the line.
 */
#include "fixtures/assertions.h"
#include "wevent.h"
#include "wwapi.h"

// ---------------------------------------------------------------------------
// neighbour event trace
// ---------------------------------------------------------------------------
//
// Upstream (toward next) events are upper case, downstream (toward prev) events are lower case:
//
//   I/i Init   E/e Est   P/p Payload   F/f Finish   U/u Pause   R/r Resume

enum
{
    kTwfMaxEvents = 96
};

typedef struct twf_trace_s
{
    char     seq[kTwfMaxEvents + 1];
    uint32_t len;

    uint32_t next_init;
    uint32_t next_est;
    uint32_t next_payload;
    uint32_t next_finish;
    uint32_t prev_init;
    uint32_t prev_est;
    uint32_t prev_payload;
    uint32_t prev_finish;

    uint32_t next_payload_bytes;
    uint32_t prev_payload_bytes;

    // optional sink so a test can inspect the exact bytes a fake neighbour received
    uint8_t *capture;
    uint32_t capture_len;
    uint32_t capture_capacity;
} twf_trace_t;

static twf_trace_t *twfTrace(tunnel_t *t)
{
    return *(twf_trace_t **) tunnelGetState(t);
}

static void twfRecord(twf_trace_t *trace, char event)
{
    twfRequire(trace->len < kTwfMaxEvents, "neighbour event trace overflow");
    trace->seq[trace->len++] = event;
    trace->seq[trace->len]   = '\0';
}

static void twfCapture(twf_trace_t *trace, sbuf_t *buf)
{
    if (trace->capture == NULL)
    {
        return;
    }

    const uint32_t len = sbufGetLength(buf);
    twfRequire(trace->capture_len + len <= trace->capture_capacity, "neighbour capture buffer overflow");
    memoryCopy(trace->capture + trace->capture_len, sbufGetRawPtr(buf), len);
    trace->capture_len += len;
}

static void twfNextInit(tunnel_t *t, line_t *l)
{
    discard      l;
    twf_trace_t *trace = twfTrace(t);
    ++trace->next_init;
    twfRecord(trace, 'I');
}

static void twfNextEst(tunnel_t *t, line_t *l)
{
    discard      l;
    twf_trace_t *trace = twfTrace(t);
    ++trace->next_est;
    twfRecord(trace, 'E');
}

static void twfNextPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    twf_trace_t *trace = twfTrace(t);
    ++trace->next_payload;
    trace->next_payload_bytes += sbufGetLength(buf);
    twfCapture(trace, buf);
    twfRecord(trace, 'P');
    lineReuseBuffer(l, buf);
}

static void twfNextFinish(tunnel_t *t, line_t *l)
{
    discard      l;
    twf_trace_t *trace = twfTrace(t);
    ++trace->next_finish;
    twfRecord(trace, 'F');
}

static void twfNextPause(tunnel_t *t, line_t *l)
{
    discard l;
    twfRecord(twfTrace(t), 'U');
}

static void twfNextResume(tunnel_t *t, line_t *l)
{
    discard l;
    twfRecord(twfTrace(t), 'R');
}

static void twfPrevInit(tunnel_t *t, line_t *l)
{
    discard      l;
    twf_trace_t *trace = twfTrace(t);
    ++trace->prev_init;
    twfRecord(trace, 'i');
}

static void twfPrevEst(tunnel_t *t, line_t *l)
{
    discard      l;
    twf_trace_t *trace = twfTrace(t);
    ++trace->prev_est;
    twfRecord(trace, 'e');
}

static void twfPrevPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    twf_trace_t *trace = twfTrace(t);
    ++trace->prev_payload;
    trace->prev_payload_bytes += sbufGetLength(buf);
    twfCapture(trace, buf);
    twfRecord(trace, 'p');
    lineReuseBuffer(l, buf);
}

static void twfPrevFinish(tunnel_t *t, line_t *l)
{
    discard      l;
    twf_trace_t *trace = twfTrace(t);
    ++trace->prev_finish;
    twfRecord(trace, 'f');
}

static void twfPrevPause(tunnel_t *t, line_t *l)
{
    discard l;
    twfRecord(twfTrace(t), 'u');
}

static void twfPrevResume(tunnel_t *t, line_t *l)
{
    discard l;
    twfRecord(twfTrace(t), 'r');
}

/**
 * Wire a fake previous tunnel: it only ever receives downstream callbacks.
 */
static tunnel_t *twfCreatePrevTunnel(twf_trace_t *trace)
{
    tunnel_t *t = tunnelCreate(NULL, sizeof(twf_trace_t *), 0);
    twfRequire(t != NULL, "failed to create the fake previous tunnel");
    *(twf_trace_t **) tunnelGetState(t) = trace;

    t->fnInitD    = twfPrevInit;
    t->fnEstD     = twfPrevEst;
    t->fnPayloadD = twfPrevPayload;
    t->fnFinD     = twfPrevFinish;
    t->fnPauseD   = twfPrevPause;
    t->fnResumeD  = twfPrevResume;
    return t;
}

/**
 * Wire a fake next tunnel: it only ever receives upstream callbacks.
 */
static tunnel_t *twfCreateNextTunnel(twf_trace_t *trace)
{
    tunnel_t *t = tunnelCreate(NULL, sizeof(twf_trace_t *), 0);
    twfRequire(t != NULL, "failed to create the fake next tunnel");
    *(twf_trace_t **) tunnelGetState(t) = trace;

    t->fnInitU    = twfNextInit;
    t->fnEstU     = twfNextEst;
    t->fnPayloadU = twfNextPayload;
    t->fnFinU     = twfNextFinish;
    t->fnPauseU   = twfNextPause;
    t->fnResumeU  = twfNextResume;
    return t;
}
