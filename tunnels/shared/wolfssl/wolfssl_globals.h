#pragma once
#include "loggers/network_logger.h"

#include "cacert.h"
#include <assert.h>
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/options.h>

enum ssl_endpoint
{
    kSslServer = 0,
    kSslClient = 1,
};

static int wolfssl_lib_initialized = false;

static void wolfSslGlobalInit(void)
{
    if (wolfssl_lib_initialized == 0)
    {
        // #if OPENSSL_VERSION_NUMBER < 0x10100000L
        //         SSL_library_init();
        //         SSL_load_error_strings();
        // #else
        //         OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT, NULL);
        // #endif
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ERR_load_crypto_strings();

#if OPENSSL_VERSION_MAJOR < 3
        ERR_load_BIO_strings(); // deprecated since OpenSSL 3.0
#endif
        wolfssl_lib_initialized = 1;
    }
}

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

static ssl_ctx_t sslCtxNew(ssl_ctx_opt_t *param)
{
    wolfSslGlobalInit();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_method());
#else
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
#endif
    if (ctx == NULL)
    {
        return NULL;
    }
    int         mode    = SSL_VERIFY_NONE;
    const char *ca_file = NULL;
    const char *ca_path = NULL;
    if (param)
    {
        if (param->ca_file && *param->ca_file)
        {
            ca_file = param->ca_file;
        }
        if (param->ca_path && *param->ca_path)
        {
            ca_path = param->ca_path;
        }
        if (ca_file || ca_path)
        {
            // SSL_CTX_load_verify_file(ctx, ca_path);

            if (! SSL_CTX_load_verify_locations(ctx, ca_file, ca_path))
            {
                LOGE("WolfSSL Error: ssl ca_file/ca_path failed");
                goto error;
            }
        }

        if (param->crt_file && *param->crt_file)
        {
            // openssl forces pem for a chained cert!
            if (! SSL_CTX_use_certificate_chain_file(ctx, param->crt_file))
            {
                LOGE("WolfSSL Error: ssl crt_file error");
                goto error;
            }
        }

        if (param->key_file && *param->key_file)
        {
            if (! SSL_CTX_use_PrivateKey_file(ctx, param->key_file, SSL_FILETYPE_PEM))
            {
                LOGE("WolfSSL Error: ssl key_file error");
                goto error;
            }
            if (! SSL_CTX_check_private_key(ctx))
            {
                LOGE("WolfSSL Error: ssl key_file check failed");
                goto error;
            }
        }

        if (param->verify_peer)
        {
            mode = SSL_VERIFY_PEER;
            if (param->endpoint == kSslServer)
            {
                mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            }
        }
    }
    if (mode == SSL_VERIFY_PEER && ! ca_file && ! ca_path)
    {
        // SSL_CTX_set_default_verify_paths(ctx);
        // alternative: use the boundeled cacert.pem
        BIO *bio = BIO_new(BIO_s_mem());
        int  n   = BIO_write(bio, cacert_bytes, (int)cacert_len);
        assert(n == (int)cacert_len);
        (void)n;
        X509 *x = NULL;
        while (true)
        {
            x = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
            if (x == NULL)
            {
                break;
            }
            X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), x);
            X509_free(x);
            x = NULL;
        }

        BIO_free(bio);
    }

    // wolfSSL_CTX_get_mode not implemented by wolfssl :/
    // #ifdef SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
    //     SSL_CTX_set_mode(ctx, SSL_CTX_get_mode(ctx) | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    // #endif

    SSL_CTX_set_verify(ctx, mode, NULL);

    return ctx;
error:
    SSL_CTX_free(ctx);
    return NULL;
}

static void printSSLState(const SSL *ssl) // NOLINT (ssl in unused problem)
{
    const char *current_state = SSL_state_string_long(ssl);
    LOGD("%s", current_state);
}

// if you get compile error at this function , include the propper logger before this file
static void printSSLError(void)
{
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char  *buf = NULL;
    size_t len = BIO_get_mem_data(bio, &buf);
    if (len > 0)
    {
        LOGE("%.*s", len, buf);
    }
    BIO_free(bio);
}
