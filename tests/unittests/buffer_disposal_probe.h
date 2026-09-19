#pragma once
#include "buffer_pool.h"
/* Direct observation of scheduler/pipe buffer disposal; no buffer metadata. */
static _Atomic(sbuf_t *) disposal_buffer;
static atomic_uint      *disposal_counter;
void                     __real_sbufDestroy(sbuf_t *buf);
void                     __real_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);
void                     __wrap_sbufDestroy(sbuf_t *buf);
void                     __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);
static void              watchBufferDisposal(sbuf_t *buf, atomic_uint *counter)
{
    assert(atomic_load_explicit(&disposal_buffer, memory_order_acquire) == NULL);
    disposal_counter = counter;
    atomic_store_explicit(&disposal_buffer, buf, memory_order_release);
}
static void observeBufferDisposal(sbuf_t *buf)
{
    sbuf_t *expected = buf;
    if (atomic_compare_exchange_strong_explicit(
            &disposal_buffer, &expected, NULL, memory_order_acq_rel, memory_order_acquire))
        atomicAddExplicit(disposal_counter, 1, memory_order_release);
}
void __wrap_sbufDestroy(sbuf_t *buf)
{
    observeBufferDisposal(buf);
    __real_sbufDestroy(buf);
}
void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf)
{
    observeBufferDisposal(buf);
    __real_bufferpoolReuseBuffer(pool, buf);
}
