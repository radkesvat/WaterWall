#pragma once
#include "wwapi.h"

/* Bounded datagram handoff. Kept alive until worker messages have settled. */
typedef struct wireguard_dispatch_s
{
    atomic_bool   open;
    atomic_size_t bytes;
    atomic_uint   count;
} wireguard_dispatch_t;
typedef void (*wireguard_dispatch_fn)(tunnel_t *, sbuf_t *, void *);
void wireguardDispatchInit(wireguard_dispatch_t *dispatch);
/* Consumes packet and argument on every result. release may run on any thread. */
void wireguardDispatch(wireguard_dispatch_t *dispatch, wid_t worker, tunnel_t *t, sbuf_t *packet, void *argument,
                       wireguard_dispatch_fn run, void (*release)(void *));
