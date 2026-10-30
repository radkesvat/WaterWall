# Cache the owner-local unacked tail instead of walking every in-flight segment
# before ordinary output. Keep queue ordering, recovery and output policy intact.
function(ww_apply_lwip_tcp_output_tail_patch lwip_dir)
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/tcp.h"
[=[  struct tcp_seg *unacked;  /* Sent but unacknowledged segments. */]=]
[=[  struct tcp_seg *unacked;  /* Sent but unacknowledged segments. */
#if WW_LWIP_WORKER_ENGINES
  /* Last member of unacked, or NULL when that queue is empty. */
  struct tcp_seg *ww_unacked_tail;
#endif]=])

    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[#include <string.h>]=]
[=[#include <string.h>
#if WW_LWIP_WORKER_ENGINES
#include <assert.h>
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  /* useg should point to last segment on unacked queue */
  useg = pcb->unacked;
  if (useg != NULL) {
    for (; useg->next != NULL; useg = useg->next);
  }]=]
[=[  /* useg should point to last segment on unacked queue */
#if WW_LWIP_WORKER_ENGINES
  useg = pcb->ww_unacked_tail;
  assert((useg == NULL) == (pcb->unacked == NULL));
  assert(useg == NULL || useg->next == NULL);
#else
  useg = pcb->unacked;
  if (useg != NULL) {
    for (; useg->next != NULL; useg = useg->next);
  }
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[      /* do not queue empty segments on the unacked list */]=]
[=[#if WW_LWIP_WORKER_ENGINES
      /* First insert and tail append update useg; sorted recovery insertion
         before the existing tail leaves it unchanged. */
      pcb->ww_unacked_tail = useg;
#endif
      /* do not queue empty segments on the unacked list */]=])

    # SYN acknowledgement removes its one segment directly rather than using
    # tcp_free_acked_segments. Clear the cache before freeing the last segment.
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[          pcb->unacked = rseg->next;]=]
[=[          pcb->unacked = rseg->next;
#if WW_LWIP_WORKER_ENGINES
          if (pcb->unacked == NULL) {
            pcb->ww_unacked_tail = NULL;
          }
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[    ww_ctx_recv_acked = (tcpwnd_size_t)(ww_ctx_recv_acked + next->len);
    tcp_seg_free(next);]=]
[=[    ww_ctx_recv_acked = (tcpwnd_size_t)(ww_ctx_recv_acked + next->len);
#if WW_LWIP_WORKER_ENGINES
    if (pcb->ww_unacked_tail == next) {
      pcb->ww_unacked_tail = NULL;
    }
#endif
    tcp_seg_free(next);]=])

    # Fast retransmission removes a prefix of one. RTO moves the complete
    # list only after every busy-pbuf check succeeds.
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  pcb->unacked = seg->next;]=]
[=[  pcb->unacked = seg->next;
#if WW_LWIP_WORKER_ENGINES
  if (pcb->unacked == NULL) {
    pcb->ww_unacked_tail = NULL;
  }
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  pcb->unacked = NULL;]=]
[=[  pcb->unacked = NULL;
#if WW_LWIP_WORKER_ENGINES
  pcb->ww_unacked_tail = NULL;
#endif]=])

    # Both terminal release paths clear the non-owning cache before free can
    # release pbuf storage. tcp_alloc zeroes the entire PCB at creation.
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[    if (pcb->unacked != NULL) {
      tcp_segs_free(pcb->unacked);
    }]=]
[=[#if WW_LWIP_WORKER_ENGINES
    pcb->ww_unacked_tail = NULL;
#endif
    if (pcb->unacked != NULL) {
      tcp_segs_free(pcb->unacked);
    }]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[    tcp_segs_free(pcb->unsent);
    tcp_segs_free(pcb->unacked);
    pcb->unacked = pcb->unsent = NULL;]=]
[=[#if WW_LWIP_WORKER_ENGINES
    pcb->ww_unacked_tail = NULL;
#endif
    tcp_segs_free(pcb->unsent);
    tcp_segs_free(pcb->unacked);
    pcb->unacked = pcb->unsent = NULL;]=])
endfunction()
