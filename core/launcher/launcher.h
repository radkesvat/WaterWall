#pragma once

#include <stddef.h>

/* Takes ownership of the malloc-allocated exact input bytes on every result.
 * Successful execution replaces this image; any returned status is a failure.
 * Arguments and source description are borrowed until execution or return. */
int launcherExecute(char *input, size_t length, const char *source, int argc, char *const argv[]);
