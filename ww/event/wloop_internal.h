#pragma once

#include "wloop.h"

/* Internal non-owning task transport for event and worker plumbing. */
bool wloopPostEvent(wloop_t *loop, wevent_t *ev);
/* Cleanup roots accepted here are drained before the worker publishes Quiesced. */
bool wloopPostControlEvent(wloop_t *loop, wevent_t *ev);

bool wloopNormalAdmissionBegin(wloop_t *loop);
void wloopNormalAdmissionEnd(wloop_t *loop);
/* The wake transport is control infrastructure and remains admissible while normal work closes. */
bool wloopIOIsControl(const wio_t *io);
int  wioAddAlreadyAdmitted(wio_t *io, wio_cb cb, int events);

typedef void (*wloop_callback_root_cb)(void *context);

bool wloopInvokeNormalCallback(wloop_t *loop, wloop_callback_root_cb cb, void *context);
void wloopInvokeControlCallback(wloop_t *loop, wloop_callback_root_cb cb, void *context);
bool wloopInvokeWriteCallback(wio_t *io, wwrite_cb cb);
