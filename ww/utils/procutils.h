#pragma once
#include <stdbool.h>

typedef struct
{
    char output[2048];
    int  exit_code;
} cmd_result_t;

cmd_result_t execCmd(const char *str); // blocking
bool        checkCommandAvailable(const char *app);
