#include "wwapi.h"

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
    pid_t child = fork();
    require(child >= 0, "failed to fork signal-manager failure child");

    if (child == 0)
    {
        wloop_t *loops[] = {(wloop_t *) (uintptr_t) 1};

        GSTATE                  = (ww_global_state_t) {0};
        GSTATE.flag_initialized = true;
        GSTATE.workers_count    = 2;
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
