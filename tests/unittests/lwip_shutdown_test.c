#include "ww_lwip.h"

#include "lwip/memp.h"
#include "lwip/priv/tcp_priv.h"
#include "wthread.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct retained_pbuf_s
{
    struct pbuf_custom custom;
    uint8_t            payload[64];
} retained_pbuf_t;

static atomic_bool  initialized;
static sigset_t     tcpip_thread_mask;
static bool         tcpip_thread_mask_known;
static unsigned int retained_pbuf_free_count;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void requireManagedSignalsMasked(const sigset_t *mask, bool expected_blocked, const char *context)
{
    const int managed_signals[] = {SIGHUP, SIGINT, SIGQUIT, SIGALRM, SIGTERM};

    for (size_t i = 0; i < ARRAY_SIZE(managed_signals); ++i)
    {
        const int membership = sigismember(mask, managed_signals[i]);
        if (membership < 0 || (membership == 1) != expected_blocked)
        {
            fprintf(stderr,
                    "FAIL: managed signal %d was %s in %s\n",
                    managed_signals[i],
                    membership == 1 ? "blocked" : "unblocked",
                    context);
            exit(1);
        }
    }
}

static void initDone(void *arg)
{
    discard arg;
    tcpip_thread_mask_known = pthread_sigmask(SIG_BLOCK, NULL, &tcpip_thread_mask) == 0;
    atomicStoreExplicit(&initialized, true, memory_order_release);
}

static void freeRetainedPbuf(struct pbuf *p)
{
    discard p;
    retained_pbuf_free_count++;
}

static void installRetainedOoseqPbuf(void *userdata)
{
    retained_pbuf_t *retained = userdata;
    LWIP_ASSERT_CORE_LOCKED();

    struct tcp_pcb *pcb = tcp_new();
    require(pcb != NULL, "failed to allocate test TCP PCB");
    pcb->state = ESTABLISHED;
    TCP_REG_ACTIVE(pcb);

    struct tcp_seg *segment = memp_malloc(MEMP_TCP_SEG);
    require(segment != NULL, "failed to allocate test TCP segment");
    memoryZero(segment, sizeof(*segment));

    retained->custom.custom_free_function = freeRetainedPbuf;
    segment->p                            = pbuf_alloced_custom(
        PBUF_RAW, sizeof(retained->payload), PBUF_REF, &retained->custom, retained->payload, sizeof(retained->payload));
    require(segment->p != NULL, "failed to allocate custom pbuf");
    pcb->ooseq = segment;
}

int main(void)
{
    retained_pbuf_t retained = {0};
    sigset_t        managed_signals;
    sigset_t        original_mask;

    buildThreadBlockedStopSignalSet(&managed_signals);
    require(pthread_sigmask(SIG_UNBLOCK, &managed_signals, &original_mask) == 0,
            "failed to unblock managed signals before lwIP thread creation");

    tcpip_init(initDone, NULL);
    while (! atomicLoadExplicit(&initialized, memory_order_acquire))
    {
        YIELD_THREAD();
    }

    require(tcpip_thread_mask_known, "failed to read the lwIP thread signal mask");
    requireManagedSignalsMasked(&tcpip_thread_mask, true, "the lwIP thread");

    sigset_t caller_mask;
    require(pthread_sigmask(SIG_BLOCK, NULL, &caller_mask) == 0, "failed to read the caller signal mask");
    requireManagedSignalsMasked(&caller_mask, false, "the caller after lwIP thread creation");
    require(pthread_sigmask(SIG_SETMASK, &original_mask, NULL) == 0, "failed to restore the original signal mask");

    /*
     * Queue state creation rather than doing it under the core lock here.
     * Shutdown cleanup must run after this already-queued work, or the retained
     * custom pbuf would survive the tcpip thread.
     */
    require(tcpip_callback(installRetainedOoseqPbuf, &retained) == ERR_OK,
            "failed to queue retained out-of-order pbuf");
    require(wwLwipShutdown(), "lwIP shutdown failed");
    require(retained_pbuf_free_count == 1, "shutdown did not release the retained out-of-order pbuf");

    /*
     * The port handle is cleared only after a successful join. A repeated call
     * must therefore be harmless and must not attempt to join a stale handle.
     */
    require(tcpip_shutdown(NULL, NULL) == ERR_OK, "repeated tcpip shutdown was not idempotent");

    puts("lwIP shutdown tests passed");
    return 0;
}
