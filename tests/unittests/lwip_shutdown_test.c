#include "ww_lwip.h"

#include "lwip/memp.h"
#include "lwip/priv/tcp_priv.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct retained_pbuf_s
{
    struct pbuf_custom custom;
    uint8_t            payload[64];
} retained_pbuf_t;

static atomic_bool  initialized;
static unsigned int retained_pbuf_free_count;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void initDone(void *arg)
{
    discard arg;
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

    tcpip_init(initDone, NULL);
    while (! atomicLoadExplicit(&initialized, memory_order_acquire))
    {
        YIELD_THREAD();
    }

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
