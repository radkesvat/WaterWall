#include "global_state.h"
#include "openssl_instance.h"

#include <openssl/crypto.h>

static bool openssl_init_wrapper_called;
static bool openssl_cleanup_wrapper_called;

int  __wrap_OPENSSL_init_ssl(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings);
void __wrap_OPENSSL_cleanup(void);

int __wrap_OPENSSL_init_ssl(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
{
    discard opts;
    discard settings;
    openssl_init_wrapper_called = true;
    return 0;
}

void __wrap_OPENSSL_cleanup(void)
{
    openssl_cleanup_wrapper_called = true;
}

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int main(void)
{
    require(opensslGlobalInit() == kWCryptoBackendFailed, "injected OpenSSL initialization failure was not propagated");
    require(openssl_init_wrapper_called, "OpenSSL initialization failure injection was not reached");
    require(openssl_cleanup_wrapper_called, "partial OpenSSL initialization did not invoke runtime cleanup");
    require(GSTATE.flag_openssl_initialized == 0, "failed OpenSSL initialization retained its initialized flag");
    require(GSTATE.openssl_dedicated_memory == NULL, "failed OpenSSL initialization retained allocator state");

    opensslGlobalCleanup();
    require(GSTATE.flag_openssl_initialized == 0 && GSTATE.openssl_dedicated_memory == NULL,
            "OpenSSL cleanup was not idempotent after partial initialization");
    return 0;
}
