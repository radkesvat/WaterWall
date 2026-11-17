#include "WireGuardCommon/dispatch.h"

typedef struct wireguard_job_s
{
    wireguard_dispatch_t *dispatch;
    tunnel_t             *t;
    sbuf_t               *packet;
    void                 *argument;
    wireguard_dispatch_fn run;
    void (*release)(void *);
    size_t charge;
} wireguard_job_t;

void wireguardDispatchInit(wireguard_dispatch_t *dispatch)
{
    atomic_init(&dispatch->open, true);
    atomic_init(&dispatch->bytes, 0);
    atomic_init(&dispatch->count, 0);
}

static void settle(wireguard_job_t *job)
{
    if (job->release != NULL)
        job->release(job->argument);
    atomic_fetch_sub(&job->dispatch->bytes, job->charge);
    atomic_fetch_sub(&job->dispatch->count, 1);
    memoryFree(job);
}

static void cancel(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard          arg2;
    discard          arg3;
    discard          reason;
    wireguard_job_t *job = arg1;
    sbufDestroy(job->packet);
    settle(job);
}

static void execute(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard          worker;
    discard          arg2;
    discard          arg3;
    wireguard_job_t *job = arg1;
    if (LIKELY(atomic_load(&job->dispatch->open)))
        job->run(job->t, job->packet, job->argument);
    else
        reuseBuffer(job->packet);
    settle(job);
}

void wireguardDispatch(wireguard_dispatch_t *dispatch, wid_t worker, tunnel_t *t, sbuf_t *packet, void *argument,
                       wireguard_dispatch_fn run, void (*release)(void *))
{
    const size_t charge = sbufGetAllocationCharge(packet) + sizeof(wireguard_job_t);
    if (UNLIKELY(! atomic_load(&dispatch->open)))
        goto refuse;
    if (UNLIKELY(atomic_fetch_add(&dispatch->count, 1) >= 512))
    {
        atomic_fetch_sub(&dispatch->count, 1);
        goto refuse;
    }
    if (UNLIKELY(atomic_fetch_add(&dispatch->bytes, charge) > 8U * 1024U * 1024U || charge > 8U * 1024U * 1024U ||
                 atomic_load(&dispatch->bytes) > 8U * 1024U * 1024U))
    {
        atomic_fetch_sub(&dispatch->bytes, charge);
        atomic_fetch_sub(&dispatch->count, 1);
        goto refuse;
    }
    wireguard_job_t *job = memoryAllocate(sizeof(*job));
    *job                 = (wireguard_job_t) {dispatch, t, packet, argument, run, release, charge};
    const worker_message_submit_result_e result =
        sendWorkerMessageForceQueueWithCleanup(worker, execute, cancel, job, NULL, NULL);
    assert(result != kWorkerMessageSubmitRejectedCallerRetains);
    discard result;
    return;
refuse:
    reuseBuffer(packet);
    if (release != NULL)
        release(argument);
}
