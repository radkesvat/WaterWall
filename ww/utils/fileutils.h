#pragma once

#include <stdbool.h>
#include <stddef.h>

char *readFile(const char *path);
bool  writeFile(const char *path, const char *data, size_t len);
