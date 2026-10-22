#pragma once

#include "wwapi.h"

/* One operation owns this staging path. It is never a recovery candidate. */
typedef struct authenticationserver_private_file_s
{
    char *path;
} authenticationserver_private_file_t;

bool authenticationserverPrivateStage(authenticationserver_private_file_t *file, const char *destination,
                                      const void *data, size_t length);
/* True means replacement committed. Directory-sync failure after replacement is
 * logged without changing that result. Consumes a successful staging file.
 * If non-NULL, published_ms receives monotonic milliseconds at replacement,
 * before best-effort directory synchronization. Zero is a valid timestamp. */
bool authenticationserverPrivatePublish(authenticationserver_private_file_t *file, const char *destination,
                                        uint64_t *published_ms);
void authenticationserverPrivateDiscard(authenticationserver_private_file_t *file);
bool authenticationserverPrivateWrite(const char *destination, const void *data, size_t length);
bool authenticationserverPrivateRestrict(const char *path);

/* Absence is captured only from the actual open, never a cleanup errno. */
typedef enum authenticationserver_private_read_result_e
{
    kAuthenticationServerPrivateReadSuccess,
    kAuthenticationServerPrivateReadAbsent,
    kAuthenticationServerPrivateReadError
} authenticationserver_private_read_result_t;
/* Restrict an existing regular file without reading its contents. Missing is
 * allowed to callers that do not require a recovery file; all other refusals
 * remain errors. Does not follow links or require ownership by the current UID. */
authenticationserver_private_read_result_t authenticationserverPrivateRestrictIfPresent(const char *path);
authenticationserver_private_read_result_t authenticationserverPrivateRead(const char *path, char **data,
                                                                           size_t *length);
authenticationserver_private_read_result_t authenticationserverPrivateProbe(const char *path);

/* Loader-only mode: an empty regular file is readable malformed input. Ordinary
 * reads/probes must still reject emptiness so saves preserve the recovery copy. */
authenticationserver_private_read_result_t authenticationserverPrivateReadForLoad(const char *path, char **data,
                                                                                  size_t *length);
/* Exclusive, private sibling; exact bytes are flushed and closed before success.
 * Caller owns the returned path, and the archive is never automatically removed. */
bool authenticationserverPrivateArchive(const char *destination, const void *data, size_t length, char **archive_path);
