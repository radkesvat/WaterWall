#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum authenticationserver_audit_error_code_e
{
    kAuthenticationServerAuditErrorNone,
    kAuthenticationServerAuditErrorOpen,
    kAuthenticationServerAuditErrorWrite,
    kAuthenticationServerAuditErrorFlush,
    kAuthenticationServerAuditErrorRotate,
    kAuthenticationServerAuditErrorClose,
    kAuthenticationServerAuditErrorInvalidFile
} authenticationserver_audit_error_code_t;

typedef struct authenticationserver_audit_error_s
{
    authenticationserver_audit_error_code_t code;
    uint32_t                                native_error;
} authenticationserver_audit_error_t;

typedef struct authenticationserver_audit_writer_s authenticationserver_audit_writer_t;

/* A single background owner uses this writer. Open also takes an exclusive
 * process-wide file lock at path.lock; the sidecar remains after Close. Files
 * must be private regular files with no symlinks or hard-link aliases. Existing
 * nonempty active files must end in a newline; partial tails need operator repair.
 * max_files includes the active file; archives are path.1 (newest), path.2, ... . */
authenticationserver_audit_writer_t *authenticationserverAuditWriterOpen(const char *path, uint64_t max_file_size,
                                                                         unsigned                            max_files,
                                                                         authenticationserver_audit_error_t *error);
/* The caller supplies one complete JSONL record no larger than max_file_size.
 * Success means fwrite plus fflush succeeded, not crash-durable storage. Any
 * I/O failure permanently faults this writer, preventing later records from
 * following an uncertain/partial write. All output errors are always assigned. */
bool authenticationserverAuditWriterAppend(authenticationserver_audit_writer_t *writer, const char *record,
                                           size_t length, authenticationserver_audit_error_t *error);
/* Always frees the writer and releases its lock, including after an error. */
bool        authenticationserverAuditWriterClose(authenticationserver_audit_writer_t *writer,
                                                 authenticationserver_audit_error_t  *error);
const char *authenticationserverAuditErrorName(authenticationserver_audit_error_code_t code);
