#pragma once

#include "wwapi.h"

#include "audit_writer.h"

/* Queue admission never waits for capacity, allocates, or performs file I/O.
 * A rejected admission loses only the audit event, never its account mutation. */
enum
{
    kAuthenticationServerAuditLabelCap         = 256,
    kAuthenticationServerAuditRecordCap        = 16384,
    kAuthenticationServerAuditQueueCap         = 256,
    kAuthenticationServerAuditFieldAccount     = 1U << 18U,
    kAuthenticationServerAuditFieldCredentials = 1U << 19U
};

typedef struct authenticationserver_audit_s authenticationserver_audit_t;

/* Strict startup-only settings, identity, and protected-path validation. */
bool authenticationserverAuditConfigure(tunnel_t *t, node_t *node);

typedef struct authenticationserver_audit_snapshot_s
{
    bool        enabled, healthy;
    uint64_t    queued_records, written_records, dropped_records, write_failures;
    const char *last_error;
} authenticationserver_audit_snapshot_t;

/* Startup opens files and starts one thread. NULL reports invalid configuration
 * or a native file/synchronization/thread failure through the ordinary logger. */
authenticationserver_audit_t *authenticationserverAuditCreate(const char *path, uint64_t max_file_size,
                                                              unsigned max_files, const char *config, const char *node,
                                                              const uint8_t instance_id[16]);
/* Call only after every submitter has quiesced. Drains accepted records and joins
 * before freeing storage. A failed join is fatal, never a cleanup fallback. */
void authenticationserverAuditDestroy(authenticationserver_audit_t *audit);
void authenticationserverAuditSnapshot(const authenticationserver_audit_t    *audit,
                                       authenticationserver_audit_snapshot_t *snapshot);

/* error is NULL for a committed operation, otherwise a fixed, nonsecret code.
 * Committed calls run immediately after the revision bump while state_lock is
 * held. id == 0 means unknown. fields contains only kUserConfig* bits and the two
 * audit markers above; operation/error must be static strings, never body data.
 * Borrowed actor/gateway strings are copied before returning. */
void authenticationserverAuditRecordApi(authenticationserver_audit_t *audit, const node_api_call_context_t *context,
                                        const char *operation, uint64_t id, uint64_t revision, uint32_t fields,
                                        const char *error);
void authenticationserverAuditRecordProducer(authenticationserver_audit_t *audit, const char *actor,
                                             const char *operation, uint64_t id, uint64_t revision, uint32_t fields,
                                             const char *error);
