#pragma once

#include "node_api.h"

typedef struct node_api_domain_s node_api_domain_t;
typedef struct node_api_job_s    node_api_job_t;

typedef enum node_api_dispatch_status_e
{
    kNodeApiDispatchOk = 0,
    kNodeApiDispatchBusy,
    kNodeApiDispatchTimeout,
    kNodeApiDispatchShuttingDown,
    kNodeApiDispatchResponseTooLarge
} node_api_dispatch_status_t;

typedef struct node_api_reply_s
{
    node_api_dispatch_status_t  status;
    enum api_result_e           result_code;
    const uint8_t              *body;
    size_t                      body_size;
    const node_api_operation_t *operation;
} node_api_reply_t;

/* Only invoked on owner_wid. Resolve non-reused session/request tokens in the
 * owner's live inventory before touching a line. reply expires on return. A
 * refused completion is dropped; the owner's required deadline settles it. */
typedef void (*NodeApiCompletion)(void *context, uint64_t session_token, uint64_t request_token,
                                  const node_api_reply_t *reply);

node_api_domain_t *nodeApiDomainCreate(size_t memory_limit, size_t job_limit, NodeApiCompletion completion,
                                       void *context);
/* Close before quiescence. Domain and context remain alive until every retained
 * job and reservation settles. Destroy requires zero jobs and reserved bytes. */
void nodeApiDomainClose(node_api_domain_t *domain);
void nodeApiDomainDestroy(node_api_domain_t *domain);
bool nodeApiDomainTryReserve(node_api_domain_t *domain, size_t bytes);
void nodeApiDomainRelease(node_api_domain_t *domain, size_t bytes);
void nodeApiDomainGetUsage(node_api_domain_t *domain, size_t *bytes, size_t *jobs);

/* Copies request/principal/gateway identity into detached storage and reserves all job working and
 * result capacity. Returns an owner reference, or NULL on budget/admission refusal.
 * No job contains a line or owner-local session pointer. max_result and working
 * must include complete handler allocation geometry, not just logical lengths. */
node_api_job_t *nodeApiJobCreate(node_api_domain_t *domain, tunnel_t *target, const node_api_operation_t *operation,
                                 wid_t owner_wid, uint64_t session_token, uint64_t request_token, uint64_t deadline_ms,
                                 const char *principal, const char *gateway_config, const char *gateway_node,
                                 const void *body, size_t body_size, size_t max_response_body_size,
                                 size_t working_memory_allowance);
/* Publish owner pending state first. Always queues, even on the same worker.
 * Retains the owner reference on every result; rejection cleanup may be inline. */
node_api_dispatch_status_t nodeApiJobSubmit(node_api_job_t *job);
void                       nodeApiJobAbandon(node_api_job_t *job);
void                       nodeApiJobRelease(node_api_job_t *job);
