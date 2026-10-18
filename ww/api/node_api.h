#pragma once

#include "objects/node.h"

typedef enum node_api_encoding_e
{
    kNodeApiEncodingUtf8 = 0,
    kNodeApiEncodingBase64
} node_api_encoding_t;

typedef enum node_api_execution_e
{
    kNodeApiCallingWorker = 0,
    kNodeApiSpecifiedWorker
} node_api_execution_t;

typedef struct node_api_call_context_s
{
    const char *operation;
    const char *principal;
    uint64_t    deadline_ms;
    size_t      max_response_body_size;
    size_t      working_memory_allowance;
} node_api_call_context_t;

/* Runs synchronously on the selected event worker. Consumes the ordinary request
 * buffer from that worker's pool, including on failure. Any returned buffer is
 * ordinary and belongs to the same pool. Borrowed context values expire on return.
 * The handler must bound its allocations/work by the supplied allowances. */
typedef api_result_t (*NodeApiHandler)(tunnel_t *, sbuf_t *, const node_api_call_context_t *);

typedef struct node_api_operation_s
{
    const char          *name;
    NodeApiHandler       handler;
    bool                 read_only;
    const char          *request_content_type;
    const char          *response_content_type;
    node_api_encoding_t  response_encoding;
    node_api_execution_t execution;
    wid_t                wid;
} node_api_operation_t;

/* Tables and all descriptor strings remain immutable and alive until unregister.
 * Registration is startup-only; no automatic exposure of historical TunnelApi. */
bool                        nodeApiRegister(tunnel_t *instance, const node_api_operation_t *operations, size_t count);
void                        nodeApiUnregister(tunnel_t *instance);
const node_api_operation_t *nodeApiFind(const tunnel_t *instance, const char *operation);
bool                        nodeApiHasRegistration(const tunnel_t *instance);
void                        nodeApiRegistryInitialize(void);
void                        nodeApiRegistryDestroy(void);
void                        nodeApiRequireEnabled(void);
bool                        nodeApiIsRequired(void);
void                        nodeApiFreeze(void);
bool                        nodeApiAdmissionIsOpen(void);
void                        nodeApiCloseAdmission(void);
uint64_t                    nodeApiNowMs(void);
