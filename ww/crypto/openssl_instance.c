#include "openssl_instance.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "managers/memory_manager.h"
#include "utils/cacert.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

static void *opennsl_dedicated_malloc(size_t num, const char *file, int line)
{
    discard file;
    discard line;
    return memoryDedicatedAllocate(GSTATE.openssl_dedicated_memory, num);
}

static void *opennsl_dedicated_realloc(void *addr, size_t num, const char *file, int line)
{
    discard file;
    discard line;
    return memoryDedicatedReallocate(GSTATE.openssl_dedicated_memory, addr, num);
}

static void opennsl_dedicated_free(void *addr, const char *file, int line)
{
    discard file;
    discard line;
    memoryDedicatedFree(GSTATE.openssl_dedicated_memory, addr);
}

static void opensslRuntimeCleanup(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPENSSL_cleanup();
#else
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
#endif
}

wcrypto_status_t opensslGlobalInit(void)
{
    if (GSTATE.flag_openssl_initialized != 0)
    {
        return kWCryptoOk;
    }

    GSTATE.openssl_dedicated_memory = memorymanagerCreateDedicatedMemory();
    if (0 == CRYPTO_set_mem_functions(opennsl_dedicated_malloc, opennsl_dedicated_realloc, opennsl_dedicated_free))
    {
        GSTATE.openssl_dedicated_memory = NULL;
        return kWCryptoBackendFailed;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    uint64_t init_flags =
        OPENSSL_INIT_SSL_DEFAULT | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_NO_ATEXIT;
    if (OPENSSL_init_ssl(init_flags, NULL) != 1)
    {
        opensslRuntimeCleanup();
        GSTATE.openssl_dedicated_memory = NULL;
        return kWCryptoBackendFailed;
    }
#else
    if (SSL_library_init() != 1)
    {
        opensslRuntimeCleanup();
        GSTATE.openssl_dedicated_memory = NULL;
        return kWCryptoBackendFailed;
    }
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
#if OPENSSL_VERSION_MAJOR < 3
    ERR_load_BIO_strings(); // deprecated since OpenSSL 3.0
#endif
#endif
    GSTATE.flag_openssl_initialized = 1;
    return kWCryptoOk;
}

void opensslGlobalCleanup(void)
{
    if (GSTATE.flag_openssl_initialized == 0)
    {
        return;
    }

    opensslRuntimeCleanup();

    GSTATE.flag_openssl_initialized = 0;
    GSTATE.openssl_dedicated_memory = NULL;
}

typedef void *ssl_ctx_t; ///> SSL_CTX

ssl_ctx_t sslCtxNew(ssl_ctx_opt_t *param)
{
    assert(GSTATE.flag_openssl_initialized); // always done, manually checking is datarace

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
                LOGE("OpenSSL Error: ssl ca_file/ca_path failed");
                goto ssl_ctx_error;
            }
        }

        if (param->crt_file && *param->crt_file)
        {
            // openssl forces pem for a chained cert!
            if (! SSL_CTX_use_certificate_chain_file(ctx, param->crt_file))
            {
                LOGE("OpenSSL Error: ssl certificate file error");
                goto ssl_ctx_error;
            }
        }

        if (param->key_file && *param->key_file)
        {
            if (! SSL_CTX_use_PrivateKey_file(ctx, param->key_file, SSL_FILETYPE_PEM))
            {
                LOGE("OpenSSL Error: ssl private key file error");
                goto ssl_ctx_error;
            }
            if (! SSL_CTX_check_private_key(ctx))
            {
                LOGE("OpenSSL Error: ssl private key file check failed");
                goto ssl_ctx_error;
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
        int  n   = BIO_write(bio, cacert_bytes, (int) cacert_len);
        assert(n == (int) cacert_len);
        discard n;
        X509   *x = NULL;
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

#ifdef SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
    SSL_CTX_set_mode(ctx, SSL_CTX_get_mode(ctx) | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
#endif

    SSL_CTX_set_verify(ctx, mode, NULL);

    return ctx;
ssl_ctx_error:
    SSL_CTX_free(ctx);
    return NULL;
}

void printSSLState(const SSL *ssl) // NOLINT (ssl in unused problem)
{
    const char *current_state = SSL_state_string_long(ssl);
    LOGD("%s", current_state);
}

// if you get compile error at this function , include the propper logger before this file
void printSSLError(void)
{
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf     = NULL;
    long  bio_len = BIO_get_mem_data(bio, &buf);
    if (bio_len > 0)
    {
        int print_len = bio_len > INT_MAX ? INT_MAX : (int) bio_len;
        LOGE("%.*s", print_len, buf);
    }
    BIO_free(bio);
}

_Noreturn void printSSLErrorAndAbort(void)
{
    printSSLError();
    abort();
}
