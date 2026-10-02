/*
 * Covers: openssl partial init failure; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real implementation entry points with the explicit substituted OS/allocation/timer boundary
 * shown below.
 * Checks: Assertion labels include: injected OpenSSL initialization failure was not propagated; OpenSSL
 * initialization failure injection was not reached; partial OpenSSL initialization did not invoke
 * runtime cleanup; failed OpenSSL initialization retained its initialized flag
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.openssl_partial_init_failure_unit
 */
#include "openssl_instance.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "wwapi.h"

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


int main(void)
{
    testCaseSet("openssl_partial_init_failure_test");
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
