#pragma once

#include "buffer_pool.h"

#include <openssl/ssl.h>

/* Compile the same implementation against each TLS library. Their BIO and
 * SSL_CTX objects must never cross the library boundary. */
#ifdef OPENSSL_IS_BORINGSSL
#define tlsbufferbioNew               tlsbufferbioBoringNew
#define tlsbufferbioFeed              tlsbufferbioBoringFeed
#define tlsbufferbioTake              tlsbufferbioBoringTake
#define tlsbufferbioPeek              tlsbufferbioBoringPeek
#define tlsbufferbioReserveWrite      tlsbufferbioBoringReserveWrite
#define tlsbufferbioFinishWrite       tlsbufferbioBoringFinishWrite
#define tlsbufferbioEnableDirectWrite tlsbufferbioBoringEnableDirectWrite
#endif

enum
{
    kTlsBufferBioMaxBytes   = 8U * 1024U * 1024U,
    kTlsBufferBioMaxBuffers = 1024U
};

/* The caller serializes ctx and pool access on their owner worker. ctx must
 * outlive the BIO; its ex-data owns the shared method. SSL owns attached BIOs. */
BIO *tlsbufferbioNew(SSL_CTX *ctx, buffer_pool_t *pool);

/* Consumes an ordinary buffer on every result. Empty input is recycled.
 * Admission refusal is terminal for the connection, not a retryable write. */
bool tlsbufferbioFeed(BIO *bio, sbuf_t *buf);

/* Transfers the oldest owned buffer without copying; NULL means empty.
 * Only drain after the SSL operation returns, never from a BIO callback. */
sbuf_t *tlsbufferbioTake(BIO *bio);

/* Copy up to length prefix bytes for protocol inspection without consuming
 * input or exposing a pointer whose lifetime depends on the next SSL call. */
size_t tlsbufferbioPeek(BIO *bio, void *out, size_t length);

#ifdef OPENSSL_IS_BORINGSSL
/* Reserve output without publishing bytes. NULL leaves the BIO unchanged and
 * permits the ordinary copying write path. Only one reservation may be active;
 * do not otherwise mutate/drain the BIO until FinishWrite. Alignment of the
 * body at prefix_len is preferred for new buffers; appending preserves FIFO
 * coalescing even when the existing tail is unaligned. */
uint8_t *tlsbufferbioReserveWrite(BIO *bio, size_t capacity, size_t alignment, size_t prefix_len);

/* Commit 1..capacity bytes, or cancel with zero. Cannot allocate or fail. */
void tlsbufferbioFinishWrite(BIO *bio, size_t written);

/* All write BIOs subsequently used by ssl must be created by tlsbufferbioNew.
 * The callbacks have no external lifetime root and finish within the SSL call. */
void tlsbufferbioEnableDirectWrite(SSL *ssl);
#endif
