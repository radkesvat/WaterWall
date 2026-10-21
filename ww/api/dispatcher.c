#include "dispatcher.h"
#include "instance/worker_messages.h"
#include "loggers/internal_logger.h"
#include "managers/signal_manager.h"
#include "wmutex.h"

struct node_api_domain_s
{
    wmutex_t          mutex;
    atomic_size_t     references;
    size_t            memory_limit;
    size_t            job_limit;
    size_t            bytes;
    size_t            jobs;
    bool              closed;
    NodeApiCompletion completion;
    void             *context;
};

struct node_api_job_s
{
    node_api_domain_t          *domain;
    tunnel_t                   *target;
    const node_api_operation_t *operation;
    wid_t                       owner_wid;
    wid_t                       target_wid;
    uint64_t                    session_token;
    uint64_t                    request_token;
    node_api_call_context_t     context;
    uint8_t                    *request;
    size_t                      request_size;
    char                       *principal;
    char                       *gateway_config;
    char                       *gateway_node;
    uint8_t                    *response;
    node_api_reply_t            reply;
    size_t                      charge;
    size_t                      references;
    bool                        abandoned;
    bool                        submitted;
};

static bool checkedAdd(size_t *value, size_t addition)
{
    if (addition > SIZE_MAX - *value)
        return false;
    *value += addition;
    return true;
}

node_api_domain_t *nodeApiDomainCreate(size_t memory_limit, size_t job_limit, NodeApiCompletion completion,
                                       void *context)
{
    assert(memory_limit > 0 && job_limit > 0 && completion != NULL);
    node_api_domain_t *domain = memoryAllocateZero(sizeof(*domain));
    if (! mutexTryInit(&domain->mutex))
    {
        memoryFree(domain);
        return NULL;
    }
    atomic_init(&domain->references, 1);
    domain->memory_limit = memory_limit;
    domain->job_limit    = job_limit;
    domain->completion   = completion;
    domain->context      = context;
    return domain;
}

void nodeApiDomainClose(node_api_domain_t *domain)
{
    assert(domain != NULL);
    mutexLock(&domain->mutex);
    domain->closed = true;
    mutexUnlock(&domain->mutex);
}

static void domainReleaseReference(node_api_domain_t *domain)
{
    if (atomic_fetch_sub_explicit(&domain->references, 1, memory_order_acq_rel) == 1)
    {
        mutexDestroy(&domain->mutex);
        memoryFree(domain);
    }
}

void nodeApiDomainDestroy(node_api_domain_t *domain)
{
    assert(domain != NULL);
    mutexLock(&domain->mutex);
    if (domain->jobs != 0 || domain->bytes != 0)
    {
        LOGF("NodeAPI: destroying a dispatch domain with live reservations");
        abortProgramNow(1);
    }
    domain->closed = true;
    mutexUnlock(&domain->mutex);
    /* A job retains its domain through the final mutex unlock and heap cleanup.
     * Zero accounting alone cannot prove that a foreign unlock has returned. */
    domainReleaseReference(domain);
}

bool nodeApiDomainTryReserve(node_api_domain_t *domain, size_t bytes)
{
    assert(domain != NULL);
    mutexLock(&domain->mutex);
    bool accepted = ! domain->closed && bytes <= domain->memory_limit - domain->bytes;
    if (accepted)
        domain->bytes += bytes;
    mutexUnlock(&domain->mutex);
    return accepted;
}

void nodeApiDomainRelease(node_api_domain_t *domain, size_t bytes)
{
    assert(domain != NULL);
    mutexLock(&domain->mutex);
    if (bytes > domain->bytes)
    {
        LOGF("NodeAPI: dispatch-domain reservation underflow");
        abortProgramNow(1);
    }
    domain->bytes -= bytes;
    mutexUnlock(&domain->mutex);
}

void nodeApiDomainGetUsage(node_api_domain_t *domain, size_t *bytes, size_t *jobs)
{
    assert(domain != NULL);
    mutexLock(&domain->mutex);
    if (bytes != NULL)
        *bytes = domain->bytes;
    if (jobs != NULL)
        *jobs = domain->jobs;
    mutexUnlock(&domain->mutex);
}

node_api_job_t *nodeApiJobCreate(node_api_domain_t *domain, tunnel_t *target, const node_api_operation_t *operation,
                                 wid_t owner_wid, uint64_t session_token, uint64_t request_token, uint64_t deadline_ms,
                                 const char *principal, const char *gateway_config, const char *gateway_node,
                                 const void *body, size_t body_size, size_t max_response_body_size,
                                 size_t working_memory_allowance)
{
    assert(domain != NULL && target != NULL && operation != NULL && principal != NULL);
    assert(body != NULL || body_size == 0);
    assert(currentThreadOwnsWorker(owner_wid));
    assert(session_token != 0 && request_token != 0);
    assert(max_response_body_size > 0 && working_memory_allowance > 0);
    const wid_t       target_wid = operation->execution == kNodeApiCallingWorker ? owner_wid : operation->wid;
    buffer_pool_fit_t request_fit;
    if (! workerWIDIsRegistered(target_wid) || body_size > UINT32_MAX || max_response_body_size > UINT32_MAX ||
        ! bufferpoolQueryBestFit(getWorkerBufferPool(target_wid), body_size, 0, &request_fit))
        return NULL;
    const size_t principal_size = strlen(principal) + 1;
    const size_t config_size    = gateway_config != NULL ? strlen(gateway_config) + 1 : 0;
    const size_t node_size      = gateway_node != NULL ? strlen(gateway_node) + 1 : 0;
    size_t       charge         = sizeof(node_api_job_t);
    if (! checkedAdd(&charge, principal_size) || ! checkedAdd(&charge, config_size) ||
        ! checkedAdd(&charge, node_size) || ! checkedAdd(&charge, body_size) ||
        ! checkedAdd(&charge, request_fit.allocation_charge) || ! checkedAdd(&charge, max_response_body_size) ||
        ! checkedAdd(&charge, working_memory_allowance))
        return NULL;
    mutexLock(&domain->mutex);
    const bool accepted = nodeApiAdmissionIsOpen() && ! domain->closed && domain->jobs < domain->job_limit &&
                          charge <= domain->memory_limit - domain->bytes;
    if (accepted)
    {
        ++domain->jobs;
        domain->bytes += charge;
        atomic_fetch_add_explicit(&domain->references, 1, memory_order_relaxed);
    }
    mutexUnlock(&domain->mutex);
    if (! accepted)
        return NULL;
    node_api_job_t *job = memoryAllocateZero(sizeof(*job));
    job->domain         = domain;
    job->target         = target;
    job->operation      = operation;
    job->owner_wid      = owner_wid;
    job->target_wid     = target_wid;
    job->session_token  = session_token;
    job->request_token  = request_token;
    job->charge         = charge;
    job->references     = 1;
    job->principal      = memoryAllocate(principal_size);
    memoryCopy(job->principal, principal, principal_size);
    if (config_size != 0)
    {
        job->gateway_config = memoryAllocate(config_size);
        memoryCopy(job->gateway_config, gateway_config, config_size);
    }
    if (node_size != 0)
    {
        job->gateway_node = memoryAllocate(node_size);
        memoryCopy(job->gateway_node, gateway_node, node_size);
    }
    if (body_size != 0)
    {
        job->request = memoryAllocate(body_size);
        memoryCopy(job->request, body, body_size);
    }
    job->request_size    = body_size;
    job->context         = (node_api_call_context_t) {.operation                = operation->name,
                                                      .principal                = job->principal,
                                                      .gateway_config           = job->gateway_config,
                                                      .gateway_node             = job->gateway_node,
                                                      .deadline_ms              = deadline_ms,
                                                      .max_response_body_size   = max_response_body_size,
                                                      .working_memory_allowance = working_memory_allowance};
    job->reply.operation = operation;
    return job;
}

void nodeApiJobAbandon(node_api_job_t *job)
{
    assert(job != NULL);
    mutexLock(&job->domain->mutex);
    job->abandoned = true;
    mutexUnlock(&job->domain->mutex);
}

void nodeApiJobRelease(node_api_job_t *job)
{
    assert(job != NULL);
    node_api_domain_t *domain = job->domain;
    mutexLock(&domain->mutex);
    assert(job->references > 0);
    const bool destroy = --job->references == 0;
    if (destroy)
    {
        assert(domain->jobs > 0 && domain->bytes >= job->charge);
        --domain->jobs;
        domain->bytes -= job->charge;
    }
    mutexUnlock(&domain->mutex);
    if (destroy)
    {
        if (job->request != NULL)
            memorySecureZero(job->request, job->request_size);
        memoryFree(job->request);
        memoryFree(job->principal);
        memoryFree(job->gateway_config);
        memoryFree(job->gateway_node);
        if (job->response != NULL)
            memorySecureZero(job->response, job->reply.body_size);
        memoryFree(job->response);
        memoryFree(job);
        domainReleaseReference(domain);
    }
}

static bool jobIsAbandoned(node_api_job_t *job)
{
    mutexLock(&job->domain->mutex);
    const bool abandoned = job->abandoned || job->domain->closed;
    mutexUnlock(&job->domain->mutex);
    return abandoned;
}

static void cleanupJob(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard arg2;
    discard arg3;
    discard reason;
    nodeApiJobRelease(arg1);
}

static void completeJob(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard         worker;
    discard         arg2;
    discard         arg3;
    node_api_job_t *job = arg1;
    assert(currentThreadOwnsWorker(job->owner_wid));
    if (! jobIsAbandoned(job) && nodeApiAdmissionIsOpen())
    {
        if (nodeApiNowMs() >= job->context.deadline_ms)
            job->reply.status = kNodeApiDispatchTimeout;
        job->domain->completion(job->domain->context, job->session_token, job->request_token, &job->reply);
    }
    nodeApiJobRelease(job);
}

static void executeJob(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard         worker;
    discard         arg2;
    discard         arg3;
    node_api_job_t *job = arg1;
    assert(currentThreadOwnsWorker(job->target_wid));
    if (jobIsAbandoned(job))
    {
        nodeApiJobRelease(job);
        return;
    }
    if (! nodeApiAdmissionIsOpen())
        job->reply.status = kNodeApiDispatchShuttingDown;
    else if (nodeApiNowMs() >= job->context.deadline_ms)
        job->reply.status = kNodeApiDispatchTimeout;
    else
    {
        buffer_pool_t *pool    = getCurrentWorkerBufferPool();
        sbuf_t        *request = bufferpoolGetBestFit(pool, (uint32_t) job->request_size, 0);
        if (job->request_size != 0)
            memoryCopy(sbufGetMutablePtr(request), job->request, job->request_size);
        sbufSetLength(request, (uint32_t) job->request_size);
        api_result_t result    = job->operation->handler(job->target, request, &job->context);
        job->reply.status      = kNodeApiDispatchOk;
        job->reply.result_code = result.result_code;
        if (result.buffer != NULL)
        {
            assert(! sbufIsSplice(result.buffer));
            const size_t response_size = sbufGetLength(result.buffer);
            if (response_size > job->context.max_response_body_size)
                job->reply.status = kNodeApiDispatchResponseTooLarge;
            else if (response_size != 0)
            {
                job->response = memoryAllocate(response_size);
                memoryCopy(job->response, sbufGetRawPtr(result.buffer), response_size);
                job->reply.body      = job->response;
                job->reply.body_size = response_size;
            }
            memorySecureZero(sbufGetMutablePtr(result.buffer), response_size);
            bufferpoolReuseBuffer(pool, result.buffer);
        }
    }
    if (jobIsAbandoned(job))
    {
        nodeApiJobRelease(job);
        return;
    }
    /* Transfer the execution reference to completion-or-cancellation. */
    const worker_message_submit_result_e completion_result =
        sendWorkerMessageForceQueueWithCleanup(job->owner_wid, completeJob, cleanupJob, job, NULL, NULL);
    /* Refusal cleanup already settled the execution reference. Owner deadlines
     * are authoritative; cancellation never posts replacement work. */
    discard completion_result;
}

node_api_dispatch_status_t nodeApiJobSubmit(node_api_job_t *job)
{
    assert(job != NULL && currentThreadOwnsWorker(job->owner_wid));
    mutexLock(&job->domain->mutex);
    assert(! job->submitted);
    job->submitted = true;
    ++job->references;
    const bool closed = job->domain->closed || ! nodeApiAdmissionIsOpen();
    mutexUnlock(&job->domain->mutex);
    if (closed)
    {
        nodeApiJobRelease(job);
        return kNodeApiDispatchShuttingDown;
    }
    const worker_message_submit_result_e result =
        sendWorkerMessageForceQueueWithCleanup(job->target_wid, executeJob, cleanupJob, job, NULL, NULL);
    return result == kWorkerMessageSubmitAccepted ? kNodeApiDispatchOk : kNodeApiDispatchBusy;
}
