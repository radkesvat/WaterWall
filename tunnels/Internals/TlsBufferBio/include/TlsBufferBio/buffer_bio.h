#pragma once

#include "buffer_pool.h"

#include <openssl/ssl.h>

/* Compile the same implementation against each TLS library. Their BIO and
 * SSL_CTX objects must never cross the library boundary. */
#ifdef OPENSSL_IS_BORINGSSL
#define tlsbufferbioNew  tlsbufferbioBoringNew
#define tlsbufferbioFeed tlsbufferbioBoringFeed
#define tlsbufferbioTake tlsbufferbioBoringTake
#define tlsbufferbioPeek tlsbufferbioBoringPeek
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
