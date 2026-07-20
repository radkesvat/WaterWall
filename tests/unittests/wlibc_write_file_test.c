#include "wlibc.h"

#include <stdio.h>

int main(void)
{
    static const char data[] = "flush failure";

    if (writeFile("/dev/full", data, sizeof(data) - 1U))
    {
        fprintf(stderr, "writeFile reported success after fclose failed\n");
        return 1;
    }

    return 0;
}
