#include "line.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

void tundeviceTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void tundeviceTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void rawsocketUpStreamFinish(tunnel_t *t, line_t *l);
void rawsocketDownStreamFinish(tunnel_t *t, line_t *l);

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void requireFinishIsFatal(TunnelFlowRoutineFin callback, const char *message)
{
    pid_t child = fork();
    require(child >= 0, "failed to fork packet-adapter Finish test");

    if (child == 0)
    {
        line_t line = {.wid = 7};
        callback(NULL, &line);
        _exit(0);
    }

    int status = 0;
    require(waitpid(child, &status, 0) == child, "failed to wait for packet-adapter Finish test");
    require(WIFSIGNALED(status) || (WIFEXITED(status) && WEXITSTATUS(status) != 0), message);
}

int main(void)
{
    requireFinishIsFatal(tundeviceTunnelUpStreamFinish, "TunDevice upstream Finish unexpectedly returned");
    requireFinishIsFatal(tundeviceTunnelDownStreamFinish, "TunDevice downstream Finish unexpectedly returned");
    requireFinishIsFatal(rawsocketUpStreamFinish, "RawSocket upstream Finish unexpectedly returned");
    requireFinishIsFatal(rawsocketDownStreamFinish, "RawSocket downstream Finish unexpectedly returned");
    return 0;
}
