#include "global_state.h"
#include "private/crypto_config.h"
#include "private/crypto_validation.h"
#include "wcrypto.h"

#if defined(WCRYPTO_OPENSSL_RUNTIME_REQUIRED) && defined(WCRYPTO_BACKEND_SODIUM)
#include "openssl_instance.h"
#include "sodium_instance.h"
#endif

#include <sys/wait.h>
#include <unistd.h>

static bool inject_crypto_init_failure;
static bool crypto_init_entry_called;
static int  audit_fd = -1;

typedef enum startup_failure_mode_e
{
    kStartupFailureBeforeBackends,
    kStartupFailureAfterOpenSsl,
} startup_failure_mode_t;

static startup_failure_mode_t failure_mode;

#if defined(WCRYPTO_OPENSSL_RUNTIME_REQUIRED) && defined(WCRYPTO_BACKEND_SODIUM)
static bool sodium_init_wrapper_called;
static bool openssl_was_initialized_before_sodium_failure;
static bool openssl_cleanup_wrapper_called;
static bool openssl_cleanup_observed_initialized;
static bool openssl_cleanup_cleared_state;

wcrypto_status_t opensslGlobalInit(void)
{
    crypto_init_entry_called = true;
    if (failure_mode == kStartupFailureBeforeBackends)
    {
        return kWCryptoBackendFailed;
    }

    GSTATE.flag_openssl_initialized = 1;
    GSTATE.openssl_dedicated_memory = (void *) (uintptr_t) 1;
    return kWCryptoOk;
}

wcrypto_status_t sodiumGlobalInit(void)
{
    sodium_init_wrapper_called                    = true;
    openssl_was_initialized_before_sodium_failure = GSTATE.flag_openssl_initialized != 0;
    return kWCryptoBackendFailed;
}

void opensslGlobalCleanup(void)
{
    openssl_cleanup_wrapper_called       = true;
    openssl_cleanup_observed_initialized = GSTATE.flag_openssl_initialized != 0;
    GSTATE.flag_openssl_initialized      = 0;
    GSTATE.openssl_dedicated_memory      = NULL;
    openssl_cleanup_cleared_state = GSTATE.flag_openssl_initialized == 0 && GSTATE.openssl_dedicated_memory == NULL;
}
#else
wcrypto_status_t __real_wCryptoGlobalInit(void);
wcrypto_status_t __wrap_wCryptoGlobalInit(void);

wcrypto_status_t __wrap_wCryptoGlobalInit(void)
{
    crypto_init_entry_called = true;
    if (inject_crypto_init_failure)
    {
        return kWCryptoBackendFailed;
    }
    return __real_wCryptoGlobalInit();
}
#endif

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void auditFailedStartup(void)
{
    bool injection_clean = crypto_init_entry_called;
#if defined(WCRYPTO_OPENSSL_RUNTIME_REQUIRED) && defined(WCRYPTO_BACKEND_SODIUM)
    if (failure_mode == kStartupFailureAfterOpenSsl)
    {
        injection_clean = injection_clean && sodium_init_wrapper_called &&
                          openssl_was_initialized_before_sodium_failure && openssl_cleanup_wrapper_called &&
                          openssl_cleanup_observed_initialized && openssl_cleanup_cleared_state;
    }
#endif

    const uint8_t clean = injection_clean && ! wCryptoIsInitialized() && ! GSTATE.flag_initialized &&
                          ! GSTATE.secure_random.initialized && ! GSTATE.flag_openssl_initialized &&
                          ! GSTATE.flag_libsodium_initialized && GSTATE.workers == NULL && GSTATE.workers_count == 0 &&
                          GSTATE.signal_manager == NULL && GSTATE.socekt_manager == NULL &&
                          GSTATE.node_manager == NULL && GSTATE.openssl_dedicated_memory == NULL &&
                          GSTATE.masterpool_buffer_pools_large == NULL &&
                          GSTATE.masterpool_buffer_pools_small == NULL && GSTATE.masterpool_wios == NULL &&
                          GSTATE.masterpool_context_pools == NULL && GSTATE.masterpool_messages == NULL;
    if (! clean)
    {
        fprintf(stderr,
                "startup audit mode=%d injection=%d crypto_called=%d crypto_initialized=%d "
                "global=%u random=%u openssl=%u sodium=%u\n",
                (int) failure_mode,
                injection_clean,
                crypto_init_entry_called,
                wCryptoIsInitialized(),
                GSTATE.flag_initialized,
                GSTATE.secure_random.initialized,
                GSTATE.flag_openssl_initialized,
                GSTATE.flag_libsodium_initialized);
#if defined(WCRYPTO_OPENSSL_RUNTIME_REQUIRED) && defined(WCRYPTO_BACKEND_SODIUM)
        fprintf(stderr,
                "partial audit sodium_called=%d openssl_before=%d cleanup_called=%d "
                "cleanup_observed=%d cleanup_cleared=%d\n",
                sodium_init_wrapper_called,
                openssl_was_initialized_before_sodium_failure,
                openssl_cleanup_wrapper_called,
                openssl_cleanup_observed_initialized,
                openssl_cleanup_cleared_state);
#endif
    }
    if (audit_fd >= 0)
    {
        ssize_t written = write(audit_fd, &clean, sizeof(clean));
        discard written;
    }
}

static void runStartupFailure(startup_failure_mode_t mode)
{
    int pipe_fds[2];
    require(pipe(pipe_fds) == 0, "failed to create startup audit pipe");

    pid_t child = fork();
    require(child >= 0, "failed to fork startup failure child");
    if (child == 0)
    {
        discard close(pipe_fds[0]);
        audit_fd = pipe_fds[1];
        require(atexit(auditFailedStartup) == 0, "failed to register startup audit callback");
        failure_mode                     = mode;
        inject_crypto_init_failure       = mode == kStartupFailureBeforeBackends;
        ww_construction_data_t init_data = {0};
        createGlobalState(init_data);
        _Exit(99);
    }

    discard close(pipe_fds[1]);
    uint8_t clean      = 0;
    ssize_t bytes_read = read(pipe_fds[0], &clean, sizeof(clean));
    discard close(pipe_fds[0]);

    int status = 0;
    require(waitpid(child, &status, 0) == child, "failed to wait for startup failure child");
    if (bytes_read != (ssize_t) sizeof(clean) || clean != 1)
    {
        fprintf(stderr,
                "startup parent audit mode=%d bytes=%zd clean=%u status=%d\n",
                (int) mode,
                bytes_read,
                clean,
                status);
    }
    require(bytes_read == (ssize_t) sizeof(clean) && clean == 1,
            "crypto initialization failure retained partial global state");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 1,
            "crypto initialization failure returned the wrong process status");
}

int main(void)
{
    runStartupFailure(kStartupFailureBeforeBackends);
#if defined(WCRYPTO_OPENSSL_RUNTIME_REQUIRED) && defined(WCRYPTO_BACKEND_SODIUM)
    runStartupFailure(kStartupFailureAfterOpenSsl);
#endif
    return 0;
}
