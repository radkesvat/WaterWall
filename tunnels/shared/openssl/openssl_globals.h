#pragma once
#include "loggers/network_logger.h"

#include "cacert.h"
#include "ww.h"
#include <assert.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

enum ssl_endpoint
{
    kSslServer = 0,
    kSslClient = 1,
};

static void opensslGlobalInit(void);

typedef struct
{
    const char       *crt_file;
    const char       *key_file;
    const char       *ca_file;
    const char       *ca_path;
    short             verify_peer;
    enum ssl_endpoint endpoint;
} ssl_ctx_opt_t;

typedef void *ssl_ctx_t; ///> SSL_CTX

ssl_ctx_t sslCtxNew(ssl_ctx_opt_t *param);
void printSSLState(const SSL *ssl);

// if you get compile error at this function , include the propper logger before this file
void printSSLError(void);

_Noreturn void printSSLErrorAndAbort(void);
