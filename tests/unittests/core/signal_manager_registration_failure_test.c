/*
 * Covers: signal manager registration failure; the explicit inputs, callbacks and expected results below
 * define this suite.
 * Setup: Real implementation entry points with the explicit substituted OS/allocation/timer boundary
 * shown below.
 * Checks: Assertion labels include: signal-manager registration failure did not exit normally;
 * signal-manager registration failure did not return cleanly
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.signal_manager_registration_failure_unit
 */
#include "wwapi.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#include <sys/wait.h>
#include <unistd.h>

static bool force_wread_failure;

wio_t *__real_wRead(wloop_t *loop, int fd, wread_cb read_cb);
wio_t *__wrap_wRead(wloop_t *loop, int fd, wread_cb read_cb);

wio_t *__wrap_wRead(wloop_t *loop, int fd, wread_cb read_cb)
{
    if (force_wread_failure)
    {
        discard loop;
        discard read_cb;
        if (fd >= 0)
        {
            close(fd);
        }
        return NULL;
    }

    return __real_wRead(loop, fd, read_cb);
}


int main(void)
{
    testCaseSet("signal_manager_registration_failure_test");
    pid_t child = fork();
    require(child >= 0, "failed to fork signal-manager failure child");

    if (child == 0)
    {
        wloop_t *loops[] = {(wloop_t *) (uintptr_t) 1};

        GSTATE                  = (ww_global_state_t) {0};
        GSTATE.flag_initialized = true;
        GSTATE.workers_count    = 1;
        GSTATE.shortcut_loops   = loops;
        GSTATE.main_thread_id   = (uint64_t) getTID();
        force_wread_failure     = true;
        signal_manager_t *sm    = signalmanagerCreate();
        if (sm == NULL)
        {
            _Exit(97);
        }
        GSTATE.signal_manager = sm;
        if (signalmanagerStart())
        {
            _Exit(98);
        }
        signalmanagerDestroy();
        _Exit(EXIT_SUCCESS);
    }

    int status = 0;
    require(waitpid(child, &status, 0) == child, "failed to wait for signal-manager failure child");
    require(WIFEXITED(status), "signal-manager registration failure did not exit normally");
    require(WEXITSTATUS(status) == EXIT_SUCCESS, "signal-manager registration failure did not return cleanly");
    return 0;
}
