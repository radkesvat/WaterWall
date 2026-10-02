/* Covers native runner output attribution, exit/skip/signal handling and locks.
 * Setup: standalone CMake executable; outputs are written relative to its CWD.
 * CTest: waterwall.native_runner (orchestrated by native_runner_test.py).
 */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

static void delay(void)
{
#ifdef _WIN32
    Sleep(2000);
#else
    struct timespec duration = {2, 0};
    while (nanosleep(&duration, &duration) != 0)
    {
    }
#endif
}

int main(int argc, char **argv)
{
    const char *mode  = argc > 1 ? argv[1] : "pass";
    const char *label = argc > 2 ? argv[2] : "default";
    fprintf(stdout, "%s:%s:%s:stdout:%s\n", FIXTURE_CONFIG, label, mode, FIXTURE_VALUE);
    fprintf(stderr, "%s:%s:%s:stderr:%s\n", FIXTURE_CONFIG, label, mode, FIXTURE_VALUE);
    fflush(stdout);
    fflush(stderr);
    FILE *output = fopen("generated.txt", "w");
    if (output == NULL)
    {
        return 2;
    }
    fprintf(output, "%s:%s:%s\n", FIXTURE_CONFIG, label, FIXTURE_VALUE);
    fclose(output);
    if (strcmp(mode, "hold") == 0)
    {
        FILE *active = fopen(FIXTURE_ACTIVE_FILE, "w");
        if (active == NULL)
        {
            return 2;
        }
        fclose(active);
        delay();
        remove(FIXTURE_ACTIVE_FILE);
    }
    if (strcmp(mode, "timeout") == 0)
    {
        delay();
    }
    if (strcmp(mode, "fail") == 0)
    {
        return 7;
    }
    if (strcmp(mode, "exit1") == 0)
    {
        return 1;
    }
    if (strcmp(mode, "skip") == 0)
    {
        return 77;
    }
    if (strcmp(mode, "signal") == 0)
    {
        raise(SIGTERM);
        return 2;
    }
    return 0;
}
