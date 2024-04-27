#pragma once
#include <stdbool.h>

typedef struct
{
    char output[2048];
    int  exit_code;
} cmdresult_t;

cmdresult_t execCmd(const char *str); // blocking
bool        checkCommandAvailable(const char *app);
