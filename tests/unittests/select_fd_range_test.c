#include "iowatcher.h"
#include "wevent.h"
#include "wloop.h"
#include "wsocket.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void testSelectFdRange(void)
{
    wloop_t loop = {0};

    require(iowatcherAddEvent(&loop, -1, WW_READ) == -ERANGE, "select backend accepted a negative descriptor");
    require(loop.iowatcher == NULL, "invalid descriptor initialized the select backend");

    require(iowatcherAddEvent(&loop, FD_SETSIZE, WW_READ) == -ERANGE, "select backend accepted FD_SETSIZE");
    require(loop.iowatcher == NULL, "out-of-range descriptor initialized the select backend");

    require(iowatcherAddEvent(&loop, FD_SETSIZE - 1, WW_READ) == 0, "select backend rejected FD_SETSIZE - 1");
    require(loop.iowatcher != NULL, "valid descriptor did not initialize the select backend");
    require(iowatcherDelEvent(&loop, FD_SETSIZE, WW_READ) == -ERANGE, "select backend deletion accepted FD_SETSIZE");
    require(iowatcherDelEvent(&loop, FD_SETSIZE - 1, WW_READ) == 0, "select backend failed to delete FD_SETSIZE - 1");
    require(iowatcherCleanUp(&loop) == 0, "select backend cleanup failed");
    require(loop.iowatcher == NULL, "select backend cleanup retained its context");
}

int main(void)
{
    testSelectFdRange();
    return 0;
}
