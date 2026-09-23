#pragma once

#include "tunnel_line_failure_harness.h"

typedef struct est_fixture_s est_fixture_t;
typedef void (*est_inject_fn)(est_fixture_t *, line_t *);
struct est_fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  lines;
    tunnel_t        *prev;
    tunnel_t        *node;
    tunnel_t        *next;
    line_t          *line;
    tunnel_chain_t  *chain;
    est_inject_fn    on_init;
    est_inject_fn    on_est;
    est_inject_fn    on_up;
    est_inject_fn    on_down;
    uint8_t          up[512];
    uint8_t          down[512];
    size_t           up_len;
    size_t           down_len;
    unsigned         est_count;
    unsigned         init_count;
    unsigned         up_finish_count;
    unsigned         down_finish_count;
    unsigned         pause_count;
};

static est_fixture_t *estContext(tunnel_t *t)
{
    return *(est_fixture_t **) tunnelGetState(t);
}

static sbuf_t *estBytes(line_t *l, const void *bytes, size_t length)
{
    sbuf_t *buf = bufferpoolGetBestFit(lineGetBufferPool(l), (uint32_t) length, 16);
    sbufSetLength(buf, (uint32_t) length);
    memoryCopy(sbufGetMutablePtr(buf), bytes, length);
    return buf;
}

static void estInit(tunnel_t *t, line_t *l)
{
    est_fixture_t *f = estContext(t);
    ++f->init_count;
    if (f->on_init != NULL)
        f->on_init(f, l);
}

static void estEst(tunnel_t *t, line_t *l)
{
    est_fixture_t *f = estContext(t);
    ++f->est_count;
    if (f->on_est != NULL)
        f->on_est(f, l);
}

static void estPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    est_fixture_t *f        = estContext(t);
    bool           upstream = t == f->next;
    size_t        *length   = upstream ? &f->up_len : &f->down_len;
    uint8_t       *bytes    = upstream ? f->up : f->down;
    twfRequire(sbufGetLength(buf) <= sizeof(f->up) - *length, "Est fixture capture overflow");
    memoryCopy(bytes + *length, sbufGetRawPtr(buf), sbufGetLength(buf));
    *length += sbufGetLength(buf);
    lineReuseBuffer(l, buf);
    est_inject_fn inject = upstream ? f->on_up : f->on_down;
    if (inject != NULL)
        inject(f, l);
}

static void estFinish(tunnel_t *t, line_t *l)
{
    est_fixture_t *f = estContext(t);
    if (t == f->next)
        ++f->up_finish_count;
    else
    {
        ++f->down_finish_count;
        lineDestroy(l); /* The mock previous endpoint owns its normal line. */
    }
}

static void estPause(tunnel_t *t, line_t *l)
{
    discard l;
    ++estContext(t)->pause_count;
}

static void estFlow(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}

static void estFixtureSetup(est_fixture_t *f, size_t tstate, size_t lstate)
{
    memoryZero(f, sizeof(*f));
    twfWorkerEnvSetup(&f->env, 65536, 16);
    f->prev = tunnelCreate(NULL, sizeof(est_fixture_t *), 0);
    f->node = tunnelCreate(NULL, (uint32_t) tstate, (uint32_t) lstate);
    f->next = tunnelCreate(NULL, sizeof(est_fixture_t *), 0);
    twfRequire(f->prev != NULL && f->node != NULL && f->next != NULL, "Est fixture tunnel allocation");
    tunnelBind(f->prev, f->node);
    tunnelBind(f->node, f->next);
    *(est_fixture_t **) tunnelGetState(f->prev) = f;
    *(est_fixture_t **) tunnelGetState(f->next) = f;
    f->next->fnInitU                            = estInit;
    f->prev->fnEstD                             = estEst;
    f->next->fnPayloadU                         = estPayload;
    f->prev->fnPayloadD                         = estPayload;
    f->next->fnFinU                             = estFinish;
    f->prev->fnFinD                             = estFinish;
    f->next->fnPauseU                           = estPause;
    f->next->fnResumeU                          = estFlow;
    f->prev->fnPauseD = f->prev->fnResumeD = estFlow;
    twfLinePoolSetup(&f->lines, f->node->lstate_size, 8);
    f->chain                = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    f->chain->line_pools[0] = f->lines.pools[0];
    f->node->chain          = f->chain;
    f->line                 = twfLinePoolCreateLine(&f->lines);
    lineRef(f->line); /* Observation reference survives mock-owner Finish. */
}

static void estFixtureDestroy(est_fixture_t *f)
{
    twfRequire(! lineIsAlive(f->line), "Est fixture owner line remains live");
    twfRequireEqualU32(twfLineRefCount(f->line), 1, "Est fixture leaked exact-line reference");
    lineUnref(f->line);
    twfLinePoolTeardown(&f->lines);
    tunnelDestroy(f->prev);
    tunnelDestroy(f->node);
    tunnelDestroy(f->next);
    memoryFree(f->chain);
    twfWorkerEnvTeardown(&f->env);
}
