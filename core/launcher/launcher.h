#pragma once

#include <stddef.h>

/* Takes ownership of the malloc-allocated exact input bytes on every result.
 * Linux success replaces this image. Windows success waits, cleans up, and
 * calls ExitProcess with the full child status. Any returned status is a failure.
 * Arguments and source description are borrowed until execution or return. */
int launcherExecute(char *input, size_t length, const char *source, int argc, char *const argv[]);
