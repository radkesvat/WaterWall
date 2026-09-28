# Explicit state relocation for the pinned lwIP source. Applied after pretend_patch.cmake.
function(ww_apply_lwip_engine_patch lwip_dir)
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/tcp_priv.h"
[=[extern u32_t tcp_ticks;]=]
[=[#if WW_LWIP_WORKER_ENGINES
u32_t (*wwLwipField_tcp_ticks(void));
#define tcp_ticks (*wwLwipField_tcp_ticks())
#else
extern u32_t tcp_ticks;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/tcp_priv.h"
[=[extern struct tcp_pcb *tcp_bound_pcbs;]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct tcp_pcb *(*wwLwipField_tcp_bound_pcbs(void));
#define tcp_bound_pcbs (*wwLwipField_tcp_bound_pcbs())
#else
extern struct tcp_pcb *tcp_bound_pcbs;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/tcp_priv.h"
[=[extern union tcp_listen_pcbs_t tcp_listen_pcbs;]=]
[=[#if WW_LWIP_WORKER_ENGINES
union tcp_listen_pcbs_t (*wwLwipField_tcp_listen_pcbs(void));
#define tcp_listen_pcbs (*wwLwipField_tcp_listen_pcbs())
#else
extern union tcp_listen_pcbs_t tcp_listen_pcbs;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/tcp_priv.h"
[=[extern struct tcp_pcb *tcp_active_pcbs;]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct tcp_pcb *(*wwLwipField_tcp_active_pcbs(void));
#define tcp_active_pcbs (*wwLwipField_tcp_active_pcbs())
#else
extern struct tcp_pcb *tcp_active_pcbs;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/tcp_priv.h"
[=[extern struct tcp_pcb *tcp_tw_pcbs;]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct tcp_pcb *(*wwLwipField_tcp_tw_pcbs(void));
#define tcp_tw_pcbs (*wwLwipField_tcp_tw_pcbs())
#else
extern struct tcp_pcb *tcp_tw_pcbs;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/tcp_priv.h"
[=[extern u8_t tcp_active_pcbs_changed;]=]
[=[#if WW_LWIP_WORKER_ENGINES
u8_t (*wwLwipField_tcp_active_pcbs_changed(void));
#define tcp_active_pcbs_changed (*wwLwipField_tcp_active_pcbs_changed())
#else
extern u8_t tcp_active_pcbs_changed;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[static u16_t tcp_port = TCP_LOCAL_PORT_RANGE_START;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u16_t tcp_port = TCP_LOCAL_PORT_RANGE_START;
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_tcp_state {
u32_t v_tcp_ticks;
struct tcp_pcb *v_tcp_bound_pcbs;
union tcp_listen_pcbs_t v_tcp_listen_pcbs;
struct tcp_pcb *v_tcp_active_pcbs;
struct tcp_pcb *v_tcp_tw_pcbs;
u8_t v_tcp_active_pcbs_changed;
u8_t v_tcp_timer;
u8_t v_tcp_timer_ctr;
u32_t v_ww_tcp_reconcile_epoch;
};
size_t wwLwipStateSize_tcp(void) { return sizeof(struct ww_tcp_state); }
void wwLwipStateInit_tcp(void *storage) {
  struct ww_tcp_state *state = storage;
  (void)state;
}
u32_t (*wwLwipField_tcp_ticks(void)) { return &((struct ww_tcp_state *)wwLwipModuleState(kWwLwipState_tcp))->v_tcp_ticks; }
struct tcp_pcb *(*wwLwipField_tcp_bound_pcbs(void)) { return &((struct ww_tcp_state *)wwLwipModuleState(kWwLwipState_tcp))->v_tcp_bound_pcbs; }
union tcp_listen_pcbs_t (*wwLwipField_tcp_listen_pcbs(void)) { return &((struct ww_tcp_state *)wwLwipModuleState(kWwLwipState_tcp))->v_tcp_listen_pcbs; }
struct tcp_pcb *(*wwLwipField_tcp_active_pcbs(void)) { return &((struct ww_tcp_state *)wwLwipModuleState(kWwLwipState_tcp))->v_tcp_active_pcbs; }
struct tcp_pcb *(*wwLwipField_tcp_tw_pcbs(void)) { return &((struct ww_tcp_state *)wwLwipModuleState(kWwLwipState_tcp))->v_tcp_tw_pcbs; }
u8_t (*wwLwipField_tcp_active_pcbs_changed(void)) { return &((struct ww_tcp_state *)wwLwipModuleState(kWwLwipState_tcp))->v_tcp_active_pcbs_changed; }
#define ww_ctx_tcp_timer (((struct ww_tcp_state *)wwLwipModuleState(kWwLwipState_tcp))->v_tcp_timer)
#define ww_ctx_tcp_timer_ctr (((struct ww_tcp_state *)wwLwipModuleState(kWwLwipState_tcp))->v_tcp_timer_ctr)
#define ww_ctx_ww_tcp_reconcile_epoch (((struct ww_tcp_state *)wwLwipModuleState(kWwLwipState_tcp))->v_ww_tcp_reconcile_epoch)
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[u32_t tcp_ticks;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
u32_t tcp_ticks;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[struct tcp_pcb *tcp_bound_pcbs;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
struct tcp_pcb *tcp_bound_pcbs;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[union tcp_listen_pcbs_t tcp_listen_pcbs;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
union tcp_listen_pcbs_t tcp_listen_pcbs;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[struct tcp_pcb *tcp_active_pcbs;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
struct tcp_pcb *tcp_active_pcbs;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[struct tcp_pcb *tcp_tw_pcbs;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
struct tcp_pcb *tcp_tw_pcbs;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[u8_t tcp_active_pcbs_changed;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
u8_t tcp_active_pcbs_changed;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[static u8_t tcp_timer;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u8_t tcp_timer;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[static u8_t tcp_timer_ctr;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u8_t tcp_timer_ctr;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[static u32_t ww_tcp_reconcile_epoch;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u32_t ww_tcp_reconcile_epoch;
#endif]=])
    file(READ "${lwip_dir}/src/core/tcp.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcp_port([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcp_port\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcp_port([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcp_port\\2" content "${content}")
    string(REPLACE "->ww_ctx_tcp_port" "->tcp_port" content "${content}")
    string(REPLACE ".ww_ctx_tcp_port" ".tcp_port" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp.c" "${content}")
    file(READ "${lwip_dir}/src/core/tcp.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcp_timer([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcp_timer\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcp_timer([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcp_timer\\2" content "${content}")
    string(REPLACE "->ww_ctx_tcp_timer" "->tcp_timer" content "${content}")
    string(REPLACE ".ww_ctx_tcp_timer" ".tcp_timer" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp.c" "${content}")
    file(READ "${lwip_dir}/src/core/tcp.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcp_timer_ctr([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcp_timer_ctr\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcp_timer_ctr([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcp_timer_ctr\\2" content "${content}")
    string(REPLACE "->ww_ctx_tcp_timer_ctr" "->tcp_timer_ctr" content "${content}")
    string(REPLACE ".ww_ctx_tcp_timer_ctr" ".tcp_timer_ctr" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp.c" "${content}")
    file(READ "${lwip_dir}/src/core/tcp.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ww_tcp_reconcile_epoch([^A-Za-z0-9_]|$)" "\\1ww_ctx_ww_tcp_reconcile_epoch\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ww_tcp_reconcile_epoch([^A-Za-z0-9_]|$)" "\\1ww_ctx_ww_tcp_reconcile_epoch\\2" content "${content}")
    string(REPLACE "->ww_ctx_ww_tcp_reconcile_epoch" "->ww_tcp_reconcile_epoch" content "${content}")
    string(REPLACE ".ww_ctx_ww_tcp_reconcile_epoch" ".ww_tcp_reconcile_epoch" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[struct tcp_pcb **const tcp_pcb_lists[] = {&tcp_listen_pcbs.pcbs, &tcp_bound_pcbs,
         &tcp_active_pcbs, &tcp_tw_pcbs
};]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct tcp_pcb ***wwLwipTcpLists(void) {
  struct tcp_pcb ***lists = wwLwipModuleState(kWwLwipState_tcp_lists);
  lists[0] = &tcp_listen_pcbs.pcbs; lists[1] = &tcp_bound_pcbs;
  lists[2] = &tcp_active_pcbs; lists[3] = &tcp_tw_pcbs;
  return lists;
}
#else
struct tcp_pcb **const tcp_pcb_lists[] = {&tcp_listen_pcbs.pcbs, &tcp_bound_pcbs,
         &tcp_active_pcbs, &tcp_tw_pcbs
};
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/tcp_priv.h"
[=[extern struct tcp_pcb ** const tcp_pcb_lists[NUM_TCP_PCB_LISTS];]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct tcp_pcb ***wwLwipTcpLists(void);
#define tcp_pcb_lists (wwLwipTcpLists())
#else
extern struct tcp_pcb ** const tcp_pcb_lists[NUM_TCP_PCB_LISTS];
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/tcp_priv.h"
[=[extern struct tcp_pcb *tcp_input_pcb;]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct tcp_pcb *(*wwLwipField_tcp_input_pcb(void));
#define tcp_input_pcb (*wwLwipField_tcp_input_pcb())
#else
extern struct tcp_pcb *tcp_input_pcb;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[static struct tcp_seg inseg;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct tcp_seg inseg;
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_tcp_in_state {
struct tcp_seg v_inseg;
struct tcp_hdr *v_tcphdr;
u16_t v_tcphdr_optlen;
u16_t v_tcphdr_opt1len;
u8_t *v_tcphdr_opt2;
u16_t v_tcp_optidx;
tcpwnd_size_t v_recv_acked;
u16_t v_tcplen;
u8_t v_flags;
u8_t v_recv_flags;
struct pbuf *v_recv_data;
struct tcp_pcb *v_tcp_input_pcb;
u32_t v_seqno;
u32_t v_ackno;
};
size_t wwLwipStateSize_tcp_in(void) { return sizeof(struct ww_tcp_in_state); }
void wwLwipStateInit_tcp_in(void *storage) {
  struct ww_tcp_in_state *state = storage;
  (void)state;

}
#define ww_ctx_inseg (((struct ww_tcp_in_state *)wwLwipModuleState(kWwLwipState_tcp_in))->v_inseg)
#define ww_ctx_tcphdr (((struct ww_tcp_in_state *)wwLwipModuleState(kWwLwipState_tcp_in))->v_tcphdr)
#define ww_ctx_tcphdr_optlen (((struct ww_tcp_in_state *)wwLwipModuleState(kWwLwipState_tcp_in))->v_tcphdr_optlen)
#define ww_ctx_tcphdr_opt1len (((struct ww_tcp_in_state *)wwLwipModuleState(kWwLwipState_tcp_in))->v_tcphdr_opt1len)
#define ww_ctx_tcphdr_opt2 (((struct ww_tcp_in_state *)wwLwipModuleState(kWwLwipState_tcp_in))->v_tcphdr_opt2)
#define ww_ctx_tcp_optidx (((struct ww_tcp_in_state *)wwLwipModuleState(kWwLwipState_tcp_in))->v_tcp_optidx)
#define ww_ctx_recv_acked (((struct ww_tcp_in_state *)wwLwipModuleState(kWwLwipState_tcp_in))->v_recv_acked)
#define ww_ctx_tcplen (((struct ww_tcp_in_state *)wwLwipModuleState(kWwLwipState_tcp_in))->v_tcplen)
#define ww_ctx_flags (((struct ww_tcp_in_state *)wwLwipModuleState(kWwLwipState_tcp_in))->v_flags)
#define ww_ctx_recv_flags (((struct ww_tcp_in_state *)wwLwipModuleState(kWwLwipState_tcp_in))->v_recv_flags)
#define ww_ctx_recv_data (((struct ww_tcp_in_state *)wwLwipModuleState(kWwLwipState_tcp_in))->v_recv_data)
struct tcp_pcb *(*wwLwipField_tcp_input_pcb(void)) { return &((struct ww_tcp_in_state *)wwLwipModuleState(kWwLwipState_tcp_in))->v_tcp_input_pcb; }
#define ww_ctx_seqno (((struct ww_tcp_in_state *)wwLwipModuleState(kWwLwipState_tcp_in))->v_seqno)
#define ww_ctx_ackno (((struct ww_tcp_in_state *)wwLwipModuleState(kWwLwipState_tcp_in))->v_ackno)
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[static struct tcp_hdr *tcphdr;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct tcp_hdr *tcphdr;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[static u16_t tcphdr_optlen;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u16_t tcphdr_optlen;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[static u16_t tcphdr_opt1len;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u16_t tcphdr_opt1len;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[static u8_t *tcphdr_opt2;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u8_t *tcphdr_opt2;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[static u16_t tcp_optidx;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u16_t tcp_optidx;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[static tcpwnd_size_t recv_acked;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static tcpwnd_size_t recv_acked;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[static u16_t tcplen;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u16_t tcplen;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[static u8_t flags;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u8_t flags;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[static u8_t recv_flags;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u8_t recv_flags;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[static struct pbuf *recv_data;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct pbuf *recv_data;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[struct tcp_pcb *tcp_input_pcb;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
struct tcp_pcb *tcp_input_pcb;
#endif]=])
    file(READ "${lwip_dir}/src/core/tcp_in.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])inseg([^A-Za-z0-9_]|$)" "\\1ww_ctx_inseg\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])inseg([^A-Za-z0-9_]|$)" "\\1ww_ctx_inseg\\2" content "${content}")
    string(REPLACE "->ww_ctx_inseg" "->inseg" content "${content}")
    string(REPLACE ".ww_ctx_inseg" ".inseg" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp_in.c" "${content}")
    file(READ "${lwip_dir}/src/core/tcp_in.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcphdr([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcphdr\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcphdr([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcphdr\\2" content "${content}")
    string(REPLACE "->ww_ctx_tcphdr" "->tcphdr" content "${content}")
    string(REPLACE ".ww_ctx_tcphdr" ".tcphdr" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp_in.c" "${content}")
    file(READ "${lwip_dir}/src/core/tcp_in.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcphdr_optlen([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcphdr_optlen\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcphdr_optlen([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcphdr_optlen\\2" content "${content}")
    string(REPLACE "->ww_ctx_tcphdr_optlen" "->tcphdr_optlen" content "${content}")
    string(REPLACE ".ww_ctx_tcphdr_optlen" ".tcphdr_optlen" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp_in.c" "${content}")
    file(READ "${lwip_dir}/src/core/tcp_in.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcphdr_opt1len([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcphdr_opt1len\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcphdr_opt1len([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcphdr_opt1len\\2" content "${content}")
    string(REPLACE "->ww_ctx_tcphdr_opt1len" "->tcphdr_opt1len" content "${content}")
    string(REPLACE ".ww_ctx_tcphdr_opt1len" ".tcphdr_opt1len" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp_in.c" "${content}")
    file(READ "${lwip_dir}/src/core/tcp_in.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcphdr_opt2([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcphdr_opt2\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcphdr_opt2([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcphdr_opt2\\2" content "${content}")
    string(REPLACE "->ww_ctx_tcphdr_opt2" "->tcphdr_opt2" content "${content}")
    string(REPLACE ".ww_ctx_tcphdr_opt2" ".tcphdr_opt2" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp_in.c" "${content}")
    file(READ "${lwip_dir}/src/core/tcp_in.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcp_optidx([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcp_optidx\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcp_optidx([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcp_optidx\\2" content "${content}")
    string(REPLACE "->ww_ctx_tcp_optidx" "->tcp_optidx" content "${content}")
    string(REPLACE ".ww_ctx_tcp_optidx" ".tcp_optidx" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp_in.c" "${content}")
    file(READ "${lwip_dir}/src/core/tcp_in.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])recv_acked([^A-Za-z0-9_]|$)" "\\1ww_ctx_recv_acked\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])recv_acked([^A-Za-z0-9_]|$)" "\\1ww_ctx_recv_acked\\2" content "${content}")
    string(REPLACE "->ww_ctx_recv_acked" "->recv_acked" content "${content}")
    string(REPLACE ".ww_ctx_recv_acked" ".recv_acked" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp_in.c" "${content}")
    file(READ "${lwip_dir}/src/core/tcp_in.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcplen([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcplen\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcplen([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcplen\\2" content "${content}")
    string(REPLACE "->ww_ctx_tcplen" "->tcplen" content "${content}")
    string(REPLACE ".ww_ctx_tcplen" ".tcplen" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp_in.c" "${content}")
    file(READ "${lwip_dir}/src/core/tcp_in.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])flags([^A-Za-z0-9_]|$)" "\\1ww_ctx_flags\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])flags([^A-Za-z0-9_]|$)" "\\1ww_ctx_flags\\2" content "${content}")
    string(REPLACE "->ww_ctx_flags" "->flags" content "${content}")
    string(REPLACE ".ww_ctx_flags" ".flags" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp_in.c" "${content}")
    file(READ "${lwip_dir}/src/core/tcp_in.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])recv_flags([^A-Za-z0-9_]|$)" "\\1ww_ctx_recv_flags\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])recv_flags([^A-Za-z0-9_]|$)" "\\1ww_ctx_recv_flags\\2" content "${content}")
    string(REPLACE "->ww_ctx_recv_flags" "->recv_flags" content "${content}")
    string(REPLACE ".ww_ctx_recv_flags" ".recv_flags" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp_in.c" "${content}")
    file(READ "${lwip_dir}/src/core/tcp_in.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])recv_data([^A-Za-z0-9_]|$)" "\\1ww_ctx_recv_data\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])recv_data([^A-Za-z0-9_]|$)" "\\1ww_ctx_recv_data\\2" content "${content}")
    string(REPLACE "->ww_ctx_recv_data" "->recv_data" content "${content}")
    string(REPLACE ".ww_ctx_recv_data" ".recv_data" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp_in.c" "${content}")
    file(READ "${lwip_dir}/src/core/tcp_in.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])seqno([^A-Za-z0-9_]|$)" "\\1ww_ctx_seqno\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])seqno([^A-Za-z0-9_]|$)" "\\1ww_ctx_seqno\\2" content "${content}")
    string(REPLACE "->ww_ctx_seqno" "->seqno" content "${content}")
    string(REPLACE ".ww_ctx_seqno" ".seqno" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp_in.c" "${content}")
    file(READ "${lwip_dir}/src/core/tcp_in.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ackno([^A-Za-z0-9_]|$)" "\\1ww_ctx_ackno\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ackno([^A-Za-z0-9_]|$)" "\\1ww_ctx_ackno\\2" content "${content}")
    string(REPLACE "->ww_ctx_ackno" "->ackno" content "${content}")
    string(REPLACE ".ww_ctx_ackno" ".ackno" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp_in.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[static u32_t ww_ctx_seqno, ww_ctx_ackno;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u32_t ww_ctx_seqno, ww_ctx_ackno;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/udp.h"
[=[extern struct udp_pcb *udp_pcbs;]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct udp_pcb *(*wwLwipField_udp_pcbs(void));
#define udp_pcbs (*wwLwipField_udp_pcbs())
#else
extern struct udp_pcb *udp_pcbs;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[static u16_t udp_port = UDP_LOCAL_PORT_RANGE_START;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u16_t udp_port = UDP_LOCAL_PORT_RANGE_START;
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_udp_state {
struct udp_pcb *v_udp_pcbs;
};
size_t wwLwipStateSize_udp(void) { return sizeof(struct ww_udp_state); }
void wwLwipStateInit_udp(void *storage) {
  struct ww_udp_state *state = storage;
  (void)state;
}
struct udp_pcb *(*wwLwipField_udp_pcbs(void)) { return &((struct ww_udp_state *)wwLwipModuleState(kWwLwipState_udp))->v_udp_pcbs; }
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[struct udp_pcb *udp_pcbs;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
struct udp_pcb *udp_pcbs;
#endif]=])
    file(READ "${lwip_dir}/src/core/udp.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])udp_port([^A-Za-z0-9_]|$)" "\\1ww_ctx_udp_port\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])udp_port([^A-Za-z0-9_]|$)" "\\1ww_ctx_udp_port\\2" content "${content}")
    string(REPLACE "->ww_ctx_udp_port" "->udp_port" content "${content}")
    string(REPLACE ".ww_ctx_udp_port" ".udp_port" content "${content}")
    file(WRITE "${lwip_dir}/src/core/udp.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/pbuf.h"
[=[extern volatile u8_t pbuf_free_ooseq_pending;]=]
[=[#if WW_LWIP_WORKER_ENGINES
volatile u8_t (*wwLwipField_pbuf_free_ooseq_pending(void));
#define pbuf_free_ooseq_pending (*wwLwipField_pbuf_free_ooseq_pending())
#else
extern volatile u8_t pbuf_free_ooseq_pending;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/pbuf.c"
[=[volatile u8_t pbuf_free_ooseq_pending;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
volatile u8_t pbuf_free_ooseq_pending;
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_pbuf_state {
volatile u8_t v_pbuf_free_ooseq_pending;
};
size_t wwLwipStateSize_pbuf(void) { return sizeof(struct ww_pbuf_state); }
void wwLwipStateInit_pbuf(void *storage) {
  struct ww_pbuf_state *state = storage;
  (void)state;

}
volatile u8_t (*wwLwipField_pbuf_free_ooseq_pending(void)) { return &((struct ww_pbuf_state *)wwLwipModuleState(kWwLwipState_pbuf))->v_pbuf_free_ooseq_pending; }
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/ip.h"
[=[extern struct ip_globals ip_data;]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct ip_globals (*wwLwipField_ip_data(void));
#define ip_data (*wwLwipField_ip_data())
#else
extern struct ip_globals ip_data;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ip.c"
[=[struct ip_globals ip_data;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
struct ip_globals ip_data;
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_ip_state {
struct ip_globals v_ip_data;
};
size_t wwLwipStateSize_ip(void) { return sizeof(struct ww_ip_state); }
void wwLwipStateInit_ip(void *storage) {
  struct ww_ip_state *state = storage;
  (void)state;

}
struct ip_globals (*wwLwipField_ip_data(void)) { return &((struct ww_ip_state *)wwLwipModuleState(kWwLwipState_ip))->v_ip_data; }
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/netif.h"
[=[extern struct netif *netif_list;]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct netif *(*wwLwipField_netif_list(void));
#define netif_list (*wwLwipField_netif_list())
#else
extern struct netif *netif_list;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/netif.h"
[=[extern struct netif *netif_default;]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct netif *(*wwLwipField_netif_default(void));
#define netif_default (*wwLwipField_netif_default())
#else
extern struct netif *netif_default;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[static netif_ext_callback_t *ext_callback;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static netif_ext_callback_t *ext_callback;
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_netif_state {
netif_ext_callback_t *v_ext_callback;
struct netif *v_netif_list;
struct netif *v_netif_default;
u8_t v_netif_num;
u32_t v_ww_netif_generation;
u8_t v_ww_netif_add_in_progress;
u8_t v_netif_client_id;
struct netif v_loop_netif;
};
size_t wwLwipStateSize_netif(void) { return sizeof(struct ww_netif_state); }
void wwLwipStateInit_netif(void *storage) {
  struct ww_netif_state *state = storage;
  (void)state;

}
#define ww_ctx_ext_callback (((struct ww_netif_state *)wwLwipModuleState(kWwLwipState_netif))->v_ext_callback)
struct netif *(*wwLwipField_netif_list(void)) { return &((struct ww_netif_state *)wwLwipModuleState(kWwLwipState_netif))->v_netif_list; }
struct netif *(*wwLwipField_netif_default(void)) { return &((struct ww_netif_state *)wwLwipModuleState(kWwLwipState_netif))->v_netif_default; }
#define ww_ctx_netif_num (((struct ww_netif_state *)wwLwipModuleState(kWwLwipState_netif))->v_netif_num)
#define ww_ctx_ww_netif_generation (((struct ww_netif_state *)wwLwipModuleState(kWwLwipState_netif))->v_ww_netif_generation)
#define ww_ctx_ww_netif_add_in_progress (((struct ww_netif_state *)wwLwipModuleState(kWwLwipState_netif))->v_ww_netif_add_in_progress)
#define ww_ctx_netif_client_id (((struct ww_netif_state *)wwLwipModuleState(kWwLwipState_netif))->v_netif_client_id)
#define ww_ctx_loop_netif (((struct ww_netif_state *)wwLwipModuleState(kWwLwipState_netif))->v_loop_netif)
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[struct netif *netif_list;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
struct netif *netif_list;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[struct netif *netif_default;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
struct netif *netif_default;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[static u8_t netif_num;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u8_t netif_num;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[static u32_t ww_netif_generation;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u32_t ww_netif_generation;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[static u8_t ww_netif_add_in_progress;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u8_t ww_netif_add_in_progress;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[static u8_t netif_client_id;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u8_t netif_client_id;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[static struct netif loop_netif;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct netif loop_netif;
#endif]=])
    file(READ "${lwip_dir}/src/core/netif.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ext_callback([^A-Za-z0-9_]|$)" "\\1ww_ctx_ext_callback\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ext_callback([^A-Za-z0-9_]|$)" "\\1ww_ctx_ext_callback\\2" content "${content}")
    string(REPLACE "->ww_ctx_ext_callback" "->ext_callback" content "${content}")
    string(REPLACE ".ww_ctx_ext_callback" ".ext_callback" content "${content}")
    file(WRITE "${lwip_dir}/src/core/netif.c" "${content}")
    file(READ "${lwip_dir}/src/core/netif.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])netif_num([^A-Za-z0-9_]|$)" "\\1ww_ctx_netif_num\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])netif_num([^A-Za-z0-9_]|$)" "\\1ww_ctx_netif_num\\2" content "${content}")
    string(REPLACE "->ww_ctx_netif_num" "->netif_num" content "${content}")
    string(REPLACE ".ww_ctx_netif_num" ".netif_num" content "${content}")
    file(WRITE "${lwip_dir}/src/core/netif.c" "${content}")
    file(READ "${lwip_dir}/src/core/netif.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ww_netif_generation([^A-Za-z0-9_]|$)" "\\1ww_ctx_ww_netif_generation\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ww_netif_generation([^A-Za-z0-9_]|$)" "\\1ww_ctx_ww_netif_generation\\2" content "${content}")
    string(REPLACE "->ww_ctx_ww_netif_generation" "->ww_netif_generation" content "${content}")
    string(REPLACE ".ww_ctx_ww_netif_generation" ".ww_netif_generation" content "${content}")
    file(WRITE "${lwip_dir}/src/core/netif.c" "${content}")
    file(READ "${lwip_dir}/src/core/netif.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ww_netif_add_in_progress([^A-Za-z0-9_]|$)" "\\1ww_ctx_ww_netif_add_in_progress\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ww_netif_add_in_progress([^A-Za-z0-9_]|$)" "\\1ww_ctx_ww_netif_add_in_progress\\2" content "${content}")
    string(REPLACE "->ww_ctx_ww_netif_add_in_progress" "->ww_netif_add_in_progress" content "${content}")
    string(REPLACE ".ww_ctx_ww_netif_add_in_progress" ".ww_netif_add_in_progress" content "${content}")
    file(WRITE "${lwip_dir}/src/core/netif.c" "${content}")
    file(READ "${lwip_dir}/src/core/netif.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])netif_client_id([^A-Za-z0-9_]|$)" "\\1ww_ctx_netif_client_id\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])netif_client_id([^A-Za-z0-9_]|$)" "\\1ww_ctx_netif_client_id\\2" content "${content}")
    string(REPLACE "->ww_ctx_netif_client_id" "->netif_client_id" content "${content}")
    string(REPLACE ".ww_ctx_netif_client_id" ".netif_client_id" content "${content}")
    file(WRITE "${lwip_dir}/src/core/netif.c" "${content}")
    file(READ "${lwip_dir}/src/core/netif.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])loop_netif([^A-Za-z0-9_]|$)" "\\1ww_ctx_loop_netif\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])loop_netif([^A-Za-z0-9_]|$)" "\\1ww_ctx_loop_netif\\2" content "${content}")
    string(REPLACE "->ww_ctx_loop_netif" "->loop_netif" content "${content}")
    string(REPLACE ".ww_ctx_loop_netif" ".loop_netif" content "${content}")
    file(WRITE "${lwip_dir}/src/core/netif.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/core/timeouts.c"
[=[static struct sys_timeo *next_timeout;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct sys_timeo *next_timeout;
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_timeouts_state {
struct sys_timeo *v_next_timeout;
u32_t v_current_timeout_due_time;
int v_tcpip_tcp_timer_active;
};
size_t wwLwipStateSize_timeouts(void) { return sizeof(struct ww_timeouts_state); }
void wwLwipStateInit_timeouts(void *storage) {
  struct ww_timeouts_state *state = storage;
  (void)state;

}
#define ww_ctx_next_timeout (((struct ww_timeouts_state *)wwLwipModuleState(kWwLwipState_timeouts))->v_next_timeout)
#define ww_ctx_current_timeout_due_time (((struct ww_timeouts_state *)wwLwipModuleState(kWwLwipState_timeouts))->v_current_timeout_due_time)
#define ww_ctx_tcpip_tcp_timer_active (((struct ww_timeouts_state *)wwLwipModuleState(kWwLwipState_timeouts))->v_tcpip_tcp_timer_active)
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/timeouts.c"
[=[static u32_t current_timeout_due_time;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u32_t current_timeout_due_time;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/timeouts.c"
[=[static int tcpip_tcp_timer_active;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static int tcpip_tcp_timer_active;
#endif]=])
    file(READ "${lwip_dir}/src/core/timeouts.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])next_timeout([^A-Za-z0-9_]|$)" "\\1ww_ctx_next_timeout\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])next_timeout([^A-Za-z0-9_]|$)" "\\1ww_ctx_next_timeout\\2" content "${content}")
    string(REPLACE "->ww_ctx_next_timeout" "->next_timeout" content "${content}")
    string(REPLACE ".ww_ctx_next_timeout" ".next_timeout" content "${content}")
    file(WRITE "${lwip_dir}/src/core/timeouts.c" "${content}")
    file(READ "${lwip_dir}/src/core/timeouts.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])current_timeout_due_time([^A-Za-z0-9_]|$)" "\\1ww_ctx_current_timeout_due_time\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])current_timeout_due_time([^A-Za-z0-9_]|$)" "\\1ww_ctx_current_timeout_due_time\\2" content "${content}")
    string(REPLACE "->ww_ctx_current_timeout_due_time" "->current_timeout_due_time" content "${content}")
    string(REPLACE ".ww_ctx_current_timeout_due_time" ".current_timeout_due_time" content "${content}")
    file(WRITE "${lwip_dir}/src/core/timeouts.c" "${content}")
    file(READ "${lwip_dir}/src/core/timeouts.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcpip_tcp_timer_active([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcpip_tcp_timer_active\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])tcpip_tcp_timer_active([^A-Za-z0-9_]|$)" "\\1ww_ctx_tcpip_tcp_timer_active\\2" content "${content}")
    string(REPLACE "->ww_ctx_tcpip_tcp_timer_active" "->tcpip_tcp_timer_active" content "${content}")
    string(REPLACE ".ww_ctx_tcpip_tcp_timer_active" ".tcpip_tcp_timer_active" content "${content}")
    file(WRITE "${lwip_dir}/src/core/timeouts.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/ip4.c"
[=[static u16_t ip_id;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u16_t ip_id;
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_ip4_state {
struct netif *v_ip4_default_multicast_netif;
};
size_t wwLwipStateSize_ip4(void) { return sizeof(struct ww_ip4_state); }
void wwLwipStateInit_ip4(void *storage) {
  struct ww_ip4_state *state = storage;
  (void)state;

}
#define ww_ctx_ip4_default_multicast_netif (((struct ww_ip4_state *)wwLwipModuleState(kWwLwipState_ip4))->v_ip4_default_multicast_netif)
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/ip4.c"
[=[static struct netif *ip4_default_multicast_netif;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct netif *ip4_default_multicast_netif;
#endif]=])
    file(READ "${lwip_dir}/src/core/ipv4/ip4.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ip_id([^A-Za-z0-9_]|$)" "\\1ww_ctx_ip_id\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ip_id([^A-Za-z0-9_]|$)" "\\1ww_ctx_ip_id\\2" content "${content}")
    string(REPLACE "->ww_ctx_ip_id" "->ip_id" content "${content}")
    string(REPLACE ".ww_ctx_ip_id" ".ip_id" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv4/ip4.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv4/ip4.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ip4_default_multicast_netif([^A-Za-z0-9_]|$)" "\\1ww_ctx_ip4_default_multicast_netif\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ip4_default_multicast_netif([^A-Za-z0-9_]|$)" "\\1ww_ctx_ip4_default_multicast_netif\\2" content "${content}")
    string(REPLACE "->ww_ctx_ip4_default_multicast_netif" "->ip4_default_multicast_netif" content "${content}")
    string(REPLACE ".ww_ctx_ip4_default_multicast_netif" ".ip4_default_multicast_netif" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv4/ip4.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/ip4_frag.c"
[=[static struct ip_reassdata *reassdatagrams;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct ip_reassdata *reassdatagrams;
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_ip4_frag_state {
struct ip_reassdata *v_reassdatagrams;
u16_t v_ip_reass_pbufcount;
};
size_t wwLwipStateSize_ip4_frag(void) { return sizeof(struct ww_ip4_frag_state); }
void wwLwipStateInit_ip4_frag(void *storage) {
  struct ww_ip4_frag_state *state = storage;
  (void)state;

}
#define ww_ctx_reassdatagrams (((struct ww_ip4_frag_state *)wwLwipModuleState(kWwLwipState_ip4_frag))->v_reassdatagrams)
#define ww_ctx_ip_reass_pbufcount (((struct ww_ip4_frag_state *)wwLwipModuleState(kWwLwipState_ip4_frag))->v_ip_reass_pbufcount)
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/ip4_frag.c"
[=[static u16_t ip_reass_pbufcount;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u16_t ip_reass_pbufcount;
#endif]=])
    file(READ "${lwip_dir}/src/core/ipv4/ip4_frag.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])reassdatagrams([^A-Za-z0-9_]|$)" "\\1ww_ctx_reassdatagrams\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])reassdatagrams([^A-Za-z0-9_]|$)" "\\1ww_ctx_reassdatagrams\\2" content "${content}")
    string(REPLACE "->ww_ctx_reassdatagrams" "->reassdatagrams" content "${content}")
    string(REPLACE ".ww_ctx_reassdatagrams" ".reassdatagrams" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv4/ip4_frag.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv4/ip4_frag.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ip_reass_pbufcount([^A-Za-z0-9_]|$)" "\\1ww_ctx_ip_reass_pbufcount\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ip_reass_pbufcount([^A-Za-z0-9_]|$)" "\\1ww_ctx_ip_reass_pbufcount\\2" content "${content}")
    string(REPLACE "->ww_ctx_ip_reass_pbufcount" "->ip_reass_pbufcount" content "${content}")
    string(REPLACE ".ww_ctx_ip_reass_pbufcount" ".ip_reass_pbufcount" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv4/ip4_frag.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/ip6_frag.c"
[=[static struct ip6_reassdata *reassdatagrams;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct ip6_reassdata *reassdatagrams;
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_ip6_frag_state {
struct ip6_reassdata *v_reassdatagrams;
u16_t v_ip6_reass_pbufcount;
};
size_t wwLwipStateSize_ip6_frag(void) { return sizeof(struct ww_ip6_frag_state); }
void wwLwipStateInit_ip6_frag(void *storage) {
  struct ww_ip6_frag_state *state = storage;
  (void)state;

}
#define ww_ctx_reassdatagrams (((struct ww_ip6_frag_state *)wwLwipModuleState(kWwLwipState_ip6_frag))->v_reassdatagrams)
#define ww_ctx_ip6_reass_pbufcount (((struct ww_ip6_frag_state *)wwLwipModuleState(kWwLwipState_ip6_frag))->v_ip6_reass_pbufcount)
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/ip6_frag.c"
[=[static u16_t ip6_reass_pbufcount;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u16_t ip6_reass_pbufcount;
#endif]=])
    file(READ "${lwip_dir}/src/core/ipv6/ip6_frag.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])reassdatagrams([^A-Za-z0-9_]|$)" "\\1ww_ctx_reassdatagrams\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])reassdatagrams([^A-Za-z0-9_]|$)" "\\1ww_ctx_reassdatagrams\\2" content "${content}")
    string(REPLACE "->ww_ctx_reassdatagrams" "->reassdatagrams" content "${content}")
    string(REPLACE ".ww_ctx_reassdatagrams" ".reassdatagrams" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv6/ip6_frag.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv6/ip6_frag.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ip6_reass_pbufcount([^A-Za-z0-9_]|$)" "\\1ww_ctx_ip6_reass_pbufcount\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])ip6_reass_pbufcount([^A-Za-z0-9_]|$)" "\\1ww_ctx_ip6_reass_pbufcount\\2" content "${content}")
    string(REPLACE "->ww_ctx_ip6_reass_pbufcount" "->ip6_reass_pbufcount" content "${content}")
    string(REPLACE ".ww_ctx_ip6_reass_pbufcount" ".ip6_reass_pbufcount" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv6/ip6_frag.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv6/ip6_frag.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])identification([^A-Za-z0-9_]|$)" "\\1ww_ctx_identification\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])identification([^A-Za-z0-9_]|$)" "\\1ww_ctx_identification\\2" content "${content}")
    string(REPLACE "->ww_ctx_identification" "->identification" content "${content}")
    string(REPLACE ".ww_ctx_identification" ".identification" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv6/ip6_frag.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/ip6_frag.c"
[=[  static u32_t ww_ctx_identification;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
  static u32_t ww_ctx_identification;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/dns.c"
[=[static struct udp_pcb        *dns_pcbs[DNS_MAX_SOURCE_PORTS];]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct udp_pcb        *dns_pcbs[DNS_MAX_SOURCE_PORTS];
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_dns_state {
struct udp_pcb        *v_dns_pcbs[DNS_MAX_SOURCE_PORTS];
u8_t                   v_dns_last_pcb_idx;
u8_t                   v_dns_seqno;
struct dns_table_entry v_dns_table[DNS_TABLE_SIZE];
struct dns_req_entry   v_dns_requests[DNS_MAX_REQUESTS];
ip_addr_t              v_dns_servers[DNS_MAX_SERVERS];
};
size_t wwLwipStateSize_dns(void) { return sizeof(struct ww_dns_state); }
void wwLwipStateInit_dns(void *storage) {
  struct ww_dns_state *state = storage;
  (void)state;

}
#define ww_ctx_dns_pcbs (((struct ww_dns_state *)wwLwipModuleState(kWwLwipState_dns))->v_dns_pcbs)
#define ww_ctx_dns_last_pcb_idx (((struct ww_dns_state *)wwLwipModuleState(kWwLwipState_dns))->v_dns_last_pcb_idx)
#define ww_ctx_dns_seqno (((struct ww_dns_state *)wwLwipModuleState(kWwLwipState_dns))->v_dns_seqno)
#define ww_ctx_dns_table (((struct ww_dns_state *)wwLwipModuleState(kWwLwipState_dns))->v_dns_table)
#define ww_ctx_dns_requests (((struct ww_dns_state *)wwLwipModuleState(kWwLwipState_dns))->v_dns_requests)
#define ww_ctx_dns_servers (((struct ww_dns_state *)wwLwipModuleState(kWwLwipState_dns))->v_dns_servers)
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/dns.c"
[=[static u8_t                   dns_last_pcb_idx;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u8_t                   dns_last_pcb_idx;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/dns.c"
[=[static u8_t                   dns_seqno;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u8_t                   dns_seqno;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/dns.c"
[=[static struct dns_table_entry dns_table[DNS_TABLE_SIZE];]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct dns_table_entry dns_table[DNS_TABLE_SIZE];
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/dns.c"
[=[static struct dns_req_entry   dns_requests[DNS_MAX_REQUESTS];]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct dns_req_entry   dns_requests[DNS_MAX_REQUESTS];
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/dns.c"
[=[static ip_addr_t              dns_servers[DNS_MAX_SERVERS];]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static ip_addr_t              dns_servers[DNS_MAX_SERVERS];
#endif]=])
    file(READ "${lwip_dir}/src/core/dns.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dns_pcbs([^A-Za-z0-9_]|$)" "\\1ww_ctx_dns_pcbs\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dns_pcbs([^A-Za-z0-9_]|$)" "\\1ww_ctx_dns_pcbs\\2" content "${content}")
    string(REPLACE "->ww_ctx_dns_pcbs" "->dns_pcbs" content "${content}")
    string(REPLACE ".ww_ctx_dns_pcbs" ".dns_pcbs" content "${content}")
    file(WRITE "${lwip_dir}/src/core/dns.c" "${content}")
    file(READ "${lwip_dir}/src/core/dns.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dns_last_pcb_idx([^A-Za-z0-9_]|$)" "\\1ww_ctx_dns_last_pcb_idx\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dns_last_pcb_idx([^A-Za-z0-9_]|$)" "\\1ww_ctx_dns_last_pcb_idx\\2" content "${content}")
    string(REPLACE "->ww_ctx_dns_last_pcb_idx" "->dns_last_pcb_idx" content "${content}")
    string(REPLACE ".ww_ctx_dns_last_pcb_idx" ".dns_last_pcb_idx" content "${content}")
    file(WRITE "${lwip_dir}/src/core/dns.c" "${content}")
    file(READ "${lwip_dir}/src/core/dns.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dns_seqno([^A-Za-z0-9_]|$)" "\\1ww_ctx_dns_seqno\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dns_seqno([^A-Za-z0-9_]|$)" "\\1ww_ctx_dns_seqno\\2" content "${content}")
    string(REPLACE "->ww_ctx_dns_seqno" "->dns_seqno" content "${content}")
    string(REPLACE ".ww_ctx_dns_seqno" ".dns_seqno" content "${content}")
    file(WRITE "${lwip_dir}/src/core/dns.c" "${content}")
    file(READ "${lwip_dir}/src/core/dns.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dns_table([^A-Za-z0-9_]|$)" "\\1ww_ctx_dns_table\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dns_table([^A-Za-z0-9_]|$)" "\\1ww_ctx_dns_table\\2" content "${content}")
    string(REPLACE "->ww_ctx_dns_table" "->dns_table" content "${content}")
    string(REPLACE ".ww_ctx_dns_table" ".dns_table" content "${content}")
    file(WRITE "${lwip_dir}/src/core/dns.c" "${content}")
    file(READ "${lwip_dir}/src/core/dns.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dns_requests([^A-Za-z0-9_]|$)" "\\1ww_ctx_dns_requests\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dns_requests([^A-Za-z0-9_]|$)" "\\1ww_ctx_dns_requests\\2" content "${content}")
    string(REPLACE "->ww_ctx_dns_requests" "->dns_requests" content "${content}")
    string(REPLACE ".ww_ctx_dns_requests" ".dns_requests" content "${content}")
    file(WRITE "${lwip_dir}/src/core/dns.c" "${content}")
    file(READ "${lwip_dir}/src/core/dns.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dns_servers([^A-Za-z0-9_]|$)" "\\1ww_ctx_dns_servers\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dns_servers([^A-Za-z0-9_]|$)" "\\1ww_ctx_dns_servers\\2" content "${content}")
    string(REPLACE "->ww_ctx_dns_servers" "->dns_servers" content "${content}")
    string(REPLACE ".ww_ctx_dns_servers" ".dns_servers" content "${content}")
    file(WRITE "${lwip_dir}/src/core/dns.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/dhcp.c"
[=[static u32_t dhcp_rx_options_val[DHCP_OPTION_IDX_MAX];]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u32_t dhcp_rx_options_val[DHCP_OPTION_IDX_MAX];
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_dhcp_state {
u32_t v_dhcp_rx_options_val[DHCP_OPTION_IDX_MAX];
u8_t  v_dhcp_rx_options_given[DHCP_OPTION_IDX_MAX];
struct udp_pcb *v_dhcp_pcb;
u8_t v_dhcp_pcb_refcount;
u32_t v_xid;
};
size_t wwLwipStateSize_dhcp(void) { return sizeof(struct ww_dhcp_state); }
void wwLwipStateInit_dhcp(void *storage) {
  struct ww_dhcp_state *state = storage;
  (void)state;

}
#define ww_ctx_dhcp_rx_options_val (((struct ww_dhcp_state *)wwLwipModuleState(kWwLwipState_dhcp))->v_dhcp_rx_options_val)
#define ww_ctx_dhcp_rx_options_given (((struct ww_dhcp_state *)wwLwipModuleState(kWwLwipState_dhcp))->v_dhcp_rx_options_given)
#define ww_ctx_dhcp_pcb (((struct ww_dhcp_state *)wwLwipModuleState(kWwLwipState_dhcp))->v_dhcp_pcb)
#define ww_ctx_dhcp_pcb_refcount (((struct ww_dhcp_state *)wwLwipModuleState(kWwLwipState_dhcp))->v_dhcp_pcb_refcount)
#define ww_ctx_xid (((struct ww_dhcp_state *)wwLwipModuleState(kWwLwipState_dhcp))->v_xid)
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/dhcp.c"
[=[static u8_t  dhcp_rx_options_given[DHCP_OPTION_IDX_MAX];]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u8_t  dhcp_rx_options_given[DHCP_OPTION_IDX_MAX];
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/dhcp.c"
[=[static struct udp_pcb *dhcp_pcb;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct udp_pcb *dhcp_pcb;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/dhcp.c"
[=[static u8_t dhcp_pcb_refcount;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u8_t dhcp_pcb_refcount;
#endif]=])
    file(READ "${lwip_dir}/src/core/ipv4/dhcp.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dhcp_rx_options_val([^A-Za-z0-9_]|$)" "\\1ww_ctx_dhcp_rx_options_val\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dhcp_rx_options_val([^A-Za-z0-9_]|$)" "\\1ww_ctx_dhcp_rx_options_val\\2" content "${content}")
    string(REPLACE "->ww_ctx_dhcp_rx_options_val" "->dhcp_rx_options_val" content "${content}")
    string(REPLACE ".ww_ctx_dhcp_rx_options_val" ".dhcp_rx_options_val" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv4/dhcp.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv4/dhcp.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dhcp_rx_options_given([^A-Za-z0-9_]|$)" "\\1ww_ctx_dhcp_rx_options_given\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dhcp_rx_options_given([^A-Za-z0-9_]|$)" "\\1ww_ctx_dhcp_rx_options_given\\2" content "${content}")
    string(REPLACE "->ww_ctx_dhcp_rx_options_given" "->dhcp_rx_options_given" content "${content}")
    string(REPLACE ".ww_ctx_dhcp_rx_options_given" ".dhcp_rx_options_given" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv4/dhcp.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv4/dhcp.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dhcp_pcb([^A-Za-z0-9_]|$)" "\\1ww_ctx_dhcp_pcb\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dhcp_pcb([^A-Za-z0-9_]|$)" "\\1ww_ctx_dhcp_pcb\\2" content "${content}")
    string(REPLACE "->ww_ctx_dhcp_pcb" "->dhcp_pcb" content "${content}")
    string(REPLACE ".ww_ctx_dhcp_pcb" ".dhcp_pcb" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv4/dhcp.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv4/dhcp.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dhcp_pcb_refcount([^A-Za-z0-9_]|$)" "\\1ww_ctx_dhcp_pcb_refcount\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])dhcp_pcb_refcount([^A-Za-z0-9_]|$)" "\\1ww_ctx_dhcp_pcb_refcount\\2" content "${content}")
    string(REPLACE "->ww_ctx_dhcp_pcb_refcount" "->dhcp_pcb_refcount" content "${content}")
    string(REPLACE ".ww_ctx_dhcp_pcb_refcount" ".dhcp_pcb_refcount" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv4/dhcp.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv4/dhcp.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])xid([^A-Za-z0-9_]|$)" "\\1ww_ctx_xid\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])xid([^A-Za-z0-9_]|$)" "\\1ww_ctx_xid\\2" content "${content}")
    string(REPLACE "->ww_ctx_xid" "->xid" content "${content}")
    string(REPLACE ".ww_ctx_xid" ".xid" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv4/dhcp.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/dhcp.c"
[=[  static u32_t ww_ctx_xid;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
  static u32_t ww_ctx_xid;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/etharp.c"
[=[static struct etharp_entry arp_table[ARP_TABLE_SIZE];]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct etharp_entry arp_table[ARP_TABLE_SIZE];
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_etharp_state {
struct etharp_entry v_arp_table[ARP_TABLE_SIZE];
netif_addr_idx_t v_etharp_cached_entry;
};
size_t wwLwipStateSize_etharp(void) { return sizeof(struct ww_etharp_state); }
void wwLwipStateInit_etharp(void *storage) {
  struct ww_etharp_state *state = storage;
  (void)state;

}
#define ww_ctx_arp_table (((struct ww_etharp_state *)wwLwipModuleState(kWwLwipState_etharp))->v_arp_table)
#define ww_ctx_etharp_cached_entry (((struct ww_etharp_state *)wwLwipModuleState(kWwLwipState_etharp))->v_etharp_cached_entry)
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/etharp.c"
[=[static netif_addr_idx_t etharp_cached_entry;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static netif_addr_idx_t etharp_cached_entry;
#endif]=])
    file(READ "${lwip_dir}/src/core/ipv4/etharp.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])arp_table([^A-Za-z0-9_]|$)" "\\1ww_ctx_arp_table\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])arp_table([^A-Za-z0-9_]|$)" "\\1ww_ctx_arp_table\\2" content "${content}")
    string(REPLACE "->ww_ctx_arp_table" "->arp_table" content "${content}")
    string(REPLACE ".ww_ctx_arp_table" ".arp_table" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv4/etharp.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv4/etharp.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])etharp_cached_entry([^A-Za-z0-9_]|$)" "\\1ww_ctx_etharp_cached_entry\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])etharp_cached_entry([^A-Za-z0-9_]|$)" "\\1ww_ctx_etharp_cached_entry\\2" content "${content}")
    string(REPLACE "->ww_ctx_etharp_cached_entry" "->etharp_cached_entry" content "${content}")
    string(REPLACE ".ww_ctx_etharp_cached_entry" ".etharp_cached_entry" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv4/etharp.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/igmp.c"
[=[static ip4_addr_t     allsystems;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static ip4_addr_t     allsystems;
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_igmp_state {
ip4_addr_t     v_allsystems;
ip4_addr_t     v_allrouters;
};
size_t wwLwipStateSize_igmp(void) { return sizeof(struct ww_igmp_state); }
void wwLwipStateInit_igmp(void *storage) {
  struct ww_igmp_state *state = storage;
  (void)state;

}
#define ww_ctx_allsystems (((struct ww_igmp_state *)wwLwipModuleState(kWwLwipState_igmp))->v_allsystems)
#define ww_ctx_allrouters (((struct ww_igmp_state *)wwLwipModuleState(kWwLwipState_igmp))->v_allrouters)
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/igmp.c"
[=[static ip4_addr_t     allrouters;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static ip4_addr_t     allrouters;
#endif]=])
    file(READ "${lwip_dir}/src/core/ipv4/igmp.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])allsystems([^A-Za-z0-9_]|$)" "\\1ww_ctx_allsystems\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])allsystems([^A-Za-z0-9_]|$)" "\\1ww_ctx_allsystems\\2" content "${content}")
    string(REPLACE "->ww_ctx_allsystems" "->allsystems" content "${content}")
    string(REPLACE ".ww_ctx_allsystems" ".allsystems" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv4/igmp.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv4/igmp.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])allrouters([^A-Za-z0-9_]|$)" "\\1ww_ctx_allrouters\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])allrouters([^A-Za-z0-9_]|$)" "\\1ww_ctx_allrouters\\2" content "${content}")
    string(REPLACE "->ww_ctx_allrouters" "->allrouters" content "${content}")
    string(REPLACE ".ww_ctx_allrouters" ".allrouters" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv4/igmp.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/nd6.c"
[=[union ra_options {
  struct lladdr_option  lladdr;
  struct mtu_option     mtu;
  struct prefix_option  prefix;
#if LWIP_ND6_RDNSS_MAX_DNS_SERVERS
  struct rdnss_option   rdnss;
#endif
};]=]
[=[/* RA scratch type is declared with the engine state above. */]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/nd6_priv.h"
[=[extern struct nd6_neighbor_cache_entry neighbor_cache[];]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct nd6_neighbor_cache_entry (*wwLwipField_neighbor_cache(void))[LWIP_ND6_NUM_NEIGHBORS];
#define neighbor_cache (*wwLwipField_neighbor_cache())
#else
extern struct nd6_neighbor_cache_entry neighbor_cache[];
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/nd6_priv.h"
[=[extern struct nd6_destination_cache_entry destination_cache[];]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct nd6_destination_cache_entry (*wwLwipField_destination_cache(void))[LWIP_ND6_NUM_DESTINATIONS];
#define destination_cache (*wwLwipField_destination_cache())
#else
extern struct nd6_destination_cache_entry destination_cache[];
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/nd6_priv.h"
[=[extern struct nd6_prefix_list_entry prefix_list[];]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct nd6_prefix_list_entry (*wwLwipField_prefix_list(void))[LWIP_ND6_NUM_PREFIXES];
#define prefix_list (*wwLwipField_prefix_list())
#else
extern struct nd6_prefix_list_entry prefix_list[];
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/nd6_priv.h"
[=[extern struct nd6_router_list_entry default_router_list[];]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct nd6_router_list_entry (*wwLwipField_default_router_list(void))[LWIP_ND6_NUM_ROUTERS];
#define default_router_list (*wwLwipField_default_router_list())
#else
extern struct nd6_router_list_entry default_router_list[];
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/nd6_priv.h"
[=[extern u32_t reachable_time;]=]
[=[#if WW_LWIP_WORKER_ENGINES
u32_t (*wwLwipField_reachable_time(void));
#define ww_ctx_reachable_time (*wwLwipField_reachable_time())
#else
extern u32_t reachable_time;
#define ww_ctx_reachable_time reachable_time
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/nd6_priv.h"
[=[extern u32_t retrans_timer;]=]
[=[#if WW_LWIP_WORKER_ENGINES
u32_t (*wwLwipField_retrans_timer(void));
#define ww_ctx_retrans_timer (*wwLwipField_retrans_timer())
#else
extern u32_t retrans_timer;
#define ww_ctx_retrans_timer retrans_timer
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/nd6.c"
[=[struct nd6_neighbor_cache_entry neighbor_cache[LWIP_ND6_NUM_NEIGHBORS];]=]
[=[#if !WW_LWIP_WORKER_ENGINES
struct nd6_neighbor_cache_entry neighbor_cache[LWIP_ND6_NUM_NEIGHBORS];
#endif
union ra_options {
  struct lladdr_option  lladdr;
  struct mtu_option     mtu;
  struct prefix_option  prefix;
#if LWIP_ND6_RDNSS_MAX_DNS_SERVERS
  struct rdnss_option   rdnss;
#endif
};
#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_nd6_state {
struct nd6_neighbor_cache_entry v_neighbor_cache[LWIP_ND6_NUM_NEIGHBORS];
struct nd6_destination_cache_entry v_destination_cache[LWIP_ND6_NUM_DESTINATIONS];
struct nd6_prefix_list_entry v_prefix_list[LWIP_ND6_NUM_PREFIXES];
struct nd6_router_list_entry v_default_router_list[LWIP_ND6_NUM_ROUTERS];
u32_t v_reachable_time;
u32_t v_retrans_timer;
u8_t v_nd6_queue_size;
netif_addr_idx_t v_nd6_cached_destination_index;
ip6_addr_t v_multicast_address;
u8_t v_nd6_tmr_rs_reduction;
union ra_options v_nd6_ra_buffer;
s8_t v_last_router;
};
size_t wwLwipStateSize_nd6(void) { return sizeof(struct ww_nd6_state); }
void wwLwipStateInit_nd6(void *storage) {
  struct ww_nd6_state *state = storage;
  (void)state;
  state->v_reachable_time = LWIP_ND6_REACHABLE_TIME;
  state->v_retrans_timer = LWIP_ND6_RETRANS_TIMER;
}
struct nd6_neighbor_cache_entry (*wwLwipField_neighbor_cache(void))[LWIP_ND6_NUM_NEIGHBORS] { return &((struct ww_nd6_state *)wwLwipModuleState(kWwLwipState_nd6))->v_neighbor_cache; }
struct nd6_destination_cache_entry (*wwLwipField_destination_cache(void))[LWIP_ND6_NUM_DESTINATIONS] { return &((struct ww_nd6_state *)wwLwipModuleState(kWwLwipState_nd6))->v_destination_cache; }
struct nd6_prefix_list_entry (*wwLwipField_prefix_list(void))[LWIP_ND6_NUM_PREFIXES] { return &((struct ww_nd6_state *)wwLwipModuleState(kWwLwipState_nd6))->v_prefix_list; }
struct nd6_router_list_entry (*wwLwipField_default_router_list(void))[LWIP_ND6_NUM_ROUTERS] { return &((struct ww_nd6_state *)wwLwipModuleState(kWwLwipState_nd6))->v_default_router_list; }
u32_t (*wwLwipField_reachable_time(void)) { return &((struct ww_nd6_state *)wwLwipModuleState(kWwLwipState_nd6))->v_reachable_time; }
u32_t (*wwLwipField_retrans_timer(void)) { return &((struct ww_nd6_state *)wwLwipModuleState(kWwLwipState_nd6))->v_retrans_timer; }
#define ww_ctx_nd6_queue_size (((struct ww_nd6_state *)wwLwipModuleState(kWwLwipState_nd6))->v_nd6_queue_size)
#define ww_ctx_nd6_cached_destination_index (((struct ww_nd6_state *)wwLwipModuleState(kWwLwipState_nd6))->v_nd6_cached_destination_index)
#define ww_ctx_multicast_address (((struct ww_nd6_state *)wwLwipModuleState(kWwLwipState_nd6))->v_multicast_address)
#define ww_ctx_nd6_tmr_rs_reduction (((struct ww_nd6_state *)wwLwipModuleState(kWwLwipState_nd6))->v_nd6_tmr_rs_reduction)
#define ww_ctx_nd6_ra_buffer (((struct ww_nd6_state *)wwLwipModuleState(kWwLwipState_nd6))->v_nd6_ra_buffer)
#define ww_ctx_last_router (((struct ww_nd6_state *)wwLwipModuleState(kWwLwipState_nd6))->v_last_router)
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/nd6.c"
[=[struct nd6_destination_cache_entry destination_cache[LWIP_ND6_NUM_DESTINATIONS];]=]
[=[#if !WW_LWIP_WORKER_ENGINES
struct nd6_destination_cache_entry destination_cache[LWIP_ND6_NUM_DESTINATIONS];
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/nd6.c"
[=[struct nd6_prefix_list_entry prefix_list[LWIP_ND6_NUM_PREFIXES];]=]
[=[#if !WW_LWIP_WORKER_ENGINES
struct nd6_prefix_list_entry prefix_list[LWIP_ND6_NUM_PREFIXES];
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/nd6.c"
[=[struct nd6_router_list_entry default_router_list[LWIP_ND6_NUM_ROUTERS];]=]
[=[#if !WW_LWIP_WORKER_ENGINES
struct nd6_router_list_entry default_router_list[LWIP_ND6_NUM_ROUTERS];
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/nd6.c"
[=[u32_t reachable_time = LWIP_ND6_REACHABLE_TIME;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
u32_t reachable_time = LWIP_ND6_REACHABLE_TIME;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/nd6.c"
[=[u32_t retrans_timer = LWIP_ND6_RETRANS_TIMER;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
u32_t retrans_timer = LWIP_ND6_RETRANS_TIMER;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/nd6.c"
[=[static u8_t nd6_queue_size = 0;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u8_t nd6_queue_size = 0;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/nd6.c"
[=[static netif_addr_idx_t nd6_cached_destination_index;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static netif_addr_idx_t nd6_cached_destination_index;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/nd6.c"
[=[static ip6_addr_t multicast_address;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static ip6_addr_t multicast_address;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/nd6.c"
[=[static u8_t nd6_tmr_rs_reduction;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u8_t nd6_tmr_rs_reduction;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/nd6.c"
[=[static union ra_options nd6_ra_buffer;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static union ra_options nd6_ra_buffer;
#endif]=])
    file(READ "${lwip_dir}/src/core/ipv6/nd6.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])reachable_time([^A-Za-z0-9_]|$)" "\\1ww_ctx_reachable_time\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])reachable_time([^A-Za-z0-9_]|$)" "\\1ww_ctx_reachable_time\\2" content "${content}")
    string(REPLACE "->ww_ctx_reachable_time" "->reachable_time" content "${content}")
    string(REPLACE ".ww_ctx_reachable_time" ".reachable_time" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv6/nd6.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv6/nd6.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])retrans_timer([^A-Za-z0-9_]|$)" "\\1ww_ctx_retrans_timer\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])retrans_timer([^A-Za-z0-9_]|$)" "\\1ww_ctx_retrans_timer\\2" content "${content}")
    string(REPLACE "->ww_ctx_retrans_timer" "->retrans_timer" content "${content}")
    string(REPLACE ".ww_ctx_retrans_timer" ".retrans_timer" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv6/nd6.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv6/nd6.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])nd6_queue_size([^A-Za-z0-9_]|$)" "\\1ww_ctx_nd6_queue_size\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])nd6_queue_size([^A-Za-z0-9_]|$)" "\\1ww_ctx_nd6_queue_size\\2" content "${content}")
    string(REPLACE "->ww_ctx_nd6_queue_size" "->nd6_queue_size" content "${content}")
    string(REPLACE ".ww_ctx_nd6_queue_size" ".nd6_queue_size" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv6/nd6.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv6/nd6.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])nd6_cached_destination_index([^A-Za-z0-9_]|$)" "\\1ww_ctx_nd6_cached_destination_index\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])nd6_cached_destination_index([^A-Za-z0-9_]|$)" "\\1ww_ctx_nd6_cached_destination_index\\2" content "${content}")
    string(REPLACE "->ww_ctx_nd6_cached_destination_index" "->nd6_cached_destination_index" content "${content}")
    string(REPLACE ".ww_ctx_nd6_cached_destination_index" ".nd6_cached_destination_index" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv6/nd6.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv6/nd6.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])multicast_address([^A-Za-z0-9_]|$)" "\\1ww_ctx_multicast_address\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])multicast_address([^A-Za-z0-9_]|$)" "\\1ww_ctx_multicast_address\\2" content "${content}")
    string(REPLACE "->ww_ctx_multicast_address" "->multicast_address" content "${content}")
    string(REPLACE ".ww_ctx_multicast_address" ".multicast_address" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv6/nd6.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv6/nd6.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])nd6_tmr_rs_reduction([^A-Za-z0-9_]|$)" "\\1ww_ctx_nd6_tmr_rs_reduction\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])nd6_tmr_rs_reduction([^A-Za-z0-9_]|$)" "\\1ww_ctx_nd6_tmr_rs_reduction\\2" content "${content}")
    string(REPLACE "->ww_ctx_nd6_tmr_rs_reduction" "->nd6_tmr_rs_reduction" content "${content}")
    string(REPLACE ".ww_ctx_nd6_tmr_rs_reduction" ".nd6_tmr_rs_reduction" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv6/nd6.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv6/nd6.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])nd6_ra_buffer([^A-Za-z0-9_]|$)" "\\1ww_ctx_nd6_ra_buffer\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])nd6_ra_buffer([^A-Za-z0-9_]|$)" "\\1ww_ctx_nd6_ra_buffer\\2" content "${content}")
    string(REPLACE "->ww_ctx_nd6_ra_buffer" "->nd6_ra_buffer" content "${content}")
    string(REPLACE ".ww_ctx_nd6_ra_buffer" ".nd6_ra_buffer" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv6/nd6.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv6/nd6.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])last_router([^A-Za-z0-9_]|$)" "\\1ww_ctx_last_router\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])last_router([^A-Za-z0-9_]|$)" "\\1ww_ctx_last_router\\2" content "${content}")
    string(REPLACE "->ww_ctx_last_router" "->last_router" content "${content}")
    string(REPLACE ".ww_ctx_last_router" ".last_router" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv6/nd6.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/nd6.c"
[=[  static s8_t ww_ctx_last_router;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
  static s8_t ww_ctx_last_router;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/netif/bridgeif.c"
[=[static u8_t bridgeif_netif_client_id = 0xff;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u8_t bridgeif_netif_client_id = 0xff;
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_bridgeif_state {
u8_t v_bridgeif_netif_client_id;
};
size_t wwLwipStateSize_bridgeif(void) { return sizeof(struct ww_bridgeif_state); }
void wwLwipStateInit_bridgeif(void *storage) {
  struct ww_bridgeif_state *state = storage;
  (void)state;
  state->v_bridgeif_netif_client_id = 0xff;
}
#define ww_ctx_bridgeif_netif_client_id (((struct ww_bridgeif_state *)wwLwipModuleState(kWwLwipState_bridgeif))->v_bridgeif_netif_client_id)
#endif
]=])
    file(READ "${lwip_dir}/src/netif/bridgeif.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])bridgeif_netif_client_id([^A-Za-z0-9_]|$)" "\\1ww_ctx_bridgeif_netif_client_id\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])bridgeif_netif_client_id([^A-Za-z0-9_]|$)" "\\1ww_ctx_bridgeif_netif_client_id\\2" content "${content}")
    string(REPLACE "->ww_ctx_bridgeif_netif_client_id" "->bridgeif_netif_client_id" content "${content}")
    string(REPLACE ".ww_ctx_bridgeif_netif_client_id" ".bridgeif_netif_client_id" content "${content}")
    file(WRITE "${lwip_dir}/src/netif/bridgeif.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/netif/lowpan6.c"
[=[static struct lowpan6_ieee802154_data lowpan6_data;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct lowpan6_ieee802154_data lowpan6_data;
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_lowpan6_state {
struct lowpan6_ieee802154_data v_lowpan6_data;
struct lowpan6_link_addr v_short_mac_addr;
};
size_t wwLwipStateSize_lowpan6(void) { return sizeof(struct ww_lowpan6_state); }
void wwLwipStateInit_lowpan6(void *storage) {
  struct ww_lowpan6_state *state = storage;
  (void)state;
  state->v_short_mac_addr.addr_len = 2;
}
#define ww_ctx_lowpan6_data (((struct ww_lowpan6_state *)wwLwipModuleState(kWwLwipState_lowpan6))->v_lowpan6_data)
#define ww_ctx_short_mac_addr (((struct ww_lowpan6_state *)wwLwipModuleState(kWwLwipState_lowpan6))->v_short_mac_addr)
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/netif/lowpan6.c"
[=[static struct lowpan6_link_addr short_mac_addr = {2, {0, 0}};]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct lowpan6_link_addr short_mac_addr = {2, {0, 0}};
#endif]=])
    file(READ "${lwip_dir}/src/netif/lowpan6.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])lowpan6_data([^A-Za-z0-9_]|$)" "\\1ww_ctx_lowpan6_data\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])lowpan6_data([^A-Za-z0-9_]|$)" "\\1ww_ctx_lowpan6_data\\2" content "${content}")
    string(REPLACE "->ww_ctx_lowpan6_data" "->lowpan6_data" content "${content}")
    string(REPLACE ".ww_ctx_lowpan6_data" ".lowpan6_data" content "${content}")
    file(WRITE "${lwip_dir}/src/netif/lowpan6.c" "${content}")
    file(READ "${lwip_dir}/src/netif/lowpan6.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])short_mac_addr([^A-Za-z0-9_]|$)" "\\1ww_ctx_short_mac_addr\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])short_mac_addr([^A-Za-z0-9_]|$)" "\\1ww_ctx_short_mac_addr\\2" content "${content}")
    string(REPLACE "->ww_ctx_short_mac_addr" "->short_mac_addr" content "${content}")
    string(REPLACE ".ww_ctx_short_mac_addr" ".short_mac_addr" content "${content}")
    file(WRITE "${lwip_dir}/src/netif/lowpan6.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/netif/lowpan6_ble.c"
[=[static ip6_addr_t rfc7668_context[LWIP_6LOWPAN_NUM_CONTEXTS];]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static ip6_addr_t rfc7668_context[LWIP_6LOWPAN_NUM_CONTEXTS];
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_lowpan6_ble_state {
ip6_addr_t v_rfc7668_context[LWIP_6LOWPAN_NUM_CONTEXTS];
struct lowpan6_link_addr v_rfc7668_local_addr;
struct lowpan6_link_addr v_rfc7668_peer_addr;
};
size_t wwLwipStateSize_lowpan6_ble(void) { return sizeof(struct ww_lowpan6_ble_state); }
void wwLwipStateInit_lowpan6_ble(void *storage) {
  struct ww_lowpan6_ble_state *state = storage;
  (void)state;

}
#define ww_ctx_rfc7668_context (((struct ww_lowpan6_ble_state *)wwLwipModuleState(kWwLwipState_lowpan6_ble))->v_rfc7668_context)
#define ww_ctx_rfc7668_local_addr (((struct ww_lowpan6_ble_state *)wwLwipModuleState(kWwLwipState_lowpan6_ble))->v_rfc7668_local_addr)
#define ww_ctx_rfc7668_peer_addr (((struct ww_lowpan6_ble_state *)wwLwipModuleState(kWwLwipState_lowpan6_ble))->v_rfc7668_peer_addr)
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/netif/lowpan6_ble.c"
[=[static struct lowpan6_link_addr rfc7668_local_addr;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct lowpan6_link_addr rfc7668_local_addr;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/netif/lowpan6_ble.c"
[=[static struct lowpan6_link_addr rfc7668_peer_addr;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct lowpan6_link_addr rfc7668_peer_addr;
#endif]=])
    file(READ "${lwip_dir}/src/netif/lowpan6_ble.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])rfc7668_context([^A-Za-z0-9_]|$)" "\\1ww_ctx_rfc7668_context\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])rfc7668_context([^A-Za-z0-9_]|$)" "\\1ww_ctx_rfc7668_context\\2" content "${content}")
    string(REPLACE "->ww_ctx_rfc7668_context" "->rfc7668_context" content "${content}")
    string(REPLACE ".ww_ctx_rfc7668_context" ".rfc7668_context" content "${content}")
    file(WRITE "${lwip_dir}/src/netif/lowpan6_ble.c" "${content}")
    file(READ "${lwip_dir}/src/netif/lowpan6_ble.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])rfc7668_local_addr([^A-Za-z0-9_]|$)" "\\1ww_ctx_rfc7668_local_addr\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])rfc7668_local_addr([^A-Za-z0-9_]|$)" "\\1ww_ctx_rfc7668_local_addr\\2" content "${content}")
    string(REPLACE "->ww_ctx_rfc7668_local_addr" "->rfc7668_local_addr" content "${content}")
    string(REPLACE ".ww_ctx_rfc7668_local_addr" ".rfc7668_local_addr" content "${content}")
    file(WRITE "${lwip_dir}/src/netif/lowpan6_ble.c" "${content}")
    file(READ "${lwip_dir}/src/netif/lowpan6_ble.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])rfc7668_peer_addr([^A-Za-z0-9_]|$)" "\\1ww_ctx_rfc7668_peer_addr\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])rfc7668_peer_addr([^A-Za-z0-9_]|$)" "\\1ww_ctx_rfc7668_peer_addr\\2" content "${content}")
    string(REPLACE "->ww_ctx_rfc7668_peer_addr" "->rfc7668_peer_addr" content "${content}")
    string(REPLACE ".ww_ctx_rfc7668_peer_addr" ".rfc7668_peer_addr" content "${content}")
    file(WRITE "${lwip_dir}/src/netif/lowpan6_ble.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/netif/zepif.c"
[=[static u8_t zep_lowpan_timer_running;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u8_t zep_lowpan_timer_running;
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_zepif_state {
u8_t v_zep_lowpan_timer_running;
};
size_t wwLwipStateSize_zepif(void) { return sizeof(struct ww_zepif_state); }
void wwLwipStateInit_zepif(void *storage) {
  struct ww_zepif_state *state = storage;
  (void)state;

}
#define ww_ctx_zep_lowpan_timer_running (((struct ww_zepif_state *)wwLwipModuleState(kWwLwipState_zepif))->v_zep_lowpan_timer_running)
#endif
]=])
    file(READ "${lwip_dir}/src/netif/zepif.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])zep_lowpan_timer_running([^A-Za-z0-9_]|$)" "\\1ww_ctx_zep_lowpan_timer_running\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])zep_lowpan_timer_running([^A-Za-z0-9_]|$)" "\\1ww_ctx_zep_lowpan_timer_running\\2" content "${content}")
    string(REPLACE "->ww_ctx_zep_lowpan_timer_running" "->zep_lowpan_timer_running" content "${content}")
    string(REPLACE ".ww_ctx_zep_lowpan_timer_running" ".zep_lowpan_timer_running" content "${content}")
    file(WRITE "${lwip_dir}/src/netif/zepif.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/netif/ppp/magic.c"
[=[static char magic_randpool[MD5_HASH_SIZE];]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static char magic_randpool[MD5_HASH_SIZE];
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_magic_state {
char v_magic_randpool[MD5_HASH_SIZE];
long v_magic_randcount;
u32_t v_magic_randomseed;
};
size_t wwLwipStateSize_magic(void) { return sizeof(struct ww_magic_state); }
void wwLwipStateInit_magic(void *storage) {
  struct ww_magic_state *state = storage;
  (void)state;

}
#define ww_ctx_magic_randpool (((struct ww_magic_state *)wwLwipModuleState(kWwLwipState_magic))->v_magic_randpool)
#define ww_ctx_magic_randcount (((struct ww_magic_state *)wwLwipModuleState(kWwLwipState_magic))->v_magic_randcount)
#define ww_ctx_magic_randomseed (((struct ww_magic_state *)wwLwipModuleState(kWwLwipState_magic))->v_magic_randomseed)
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/netif/ppp/magic.c"
[=[static long magic_randcount;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static long magic_randcount;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/netif/ppp/magic.c"
[=[static u32_t magic_randomseed;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static u32_t magic_randomseed;
#endif]=])
    file(READ "${lwip_dir}/src/netif/ppp/magic.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])magic_randpool([^A-Za-z0-9_]|$)" "\\1ww_ctx_magic_randpool\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])magic_randpool([^A-Za-z0-9_]|$)" "\\1ww_ctx_magic_randpool\\2" content "${content}")
    string(REPLACE "->ww_ctx_magic_randpool" "->magic_randpool" content "${content}")
    string(REPLACE ".ww_ctx_magic_randpool" ".magic_randpool" content "${content}")
    file(WRITE "${lwip_dir}/src/netif/ppp/magic.c" "${content}")
    file(READ "${lwip_dir}/src/netif/ppp/magic.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])magic_randcount([^A-Za-z0-9_]|$)" "\\1ww_ctx_magic_randcount\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])magic_randcount([^A-Za-z0-9_]|$)" "\\1ww_ctx_magic_randcount\\2" content "${content}")
    string(REPLACE "->ww_ctx_magic_randcount" "->magic_randcount" content "${content}")
    string(REPLACE ".ww_ctx_magic_randcount" ".magic_randcount" content "${content}")
    file(WRITE "${lwip_dir}/src/netif/ppp/magic.c" "${content}")
    file(READ "${lwip_dir}/src/netif/ppp/magic.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])magic_randomseed([^A-Za-z0-9_]|$)" "\\1ww_ctx_magic_randomseed\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])magic_randomseed([^A-Za-z0-9_]|$)" "\\1ww_ctx_magic_randomseed\\2" content "${content}")
    string(REPLACE "->ww_ctx_magic_randomseed" "->magic_randomseed" content "${content}")
    string(REPLACE ".ww_ctx_magic_randomseed" ".magic_randomseed" content "${content}")
    file(WRITE "${lwip_dir}/src/netif/ppp/magic.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/netif/ppp/pppoe.c"
[=[static struct pppoe_softc *pppoe_softc_list;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
static struct pppoe_softc *pppoe_softc_list;
#endif

#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
struct ww_pppoe_state {
struct pppoe_softc *v_pppoe_softc_list;
};
size_t wwLwipStateSize_pppoe(void) { return sizeof(struct ww_pppoe_state); }
void wwLwipStateInit_pppoe(void *storage) {
  struct ww_pppoe_state *state = storage;
  (void)state;

}
#define ww_ctx_pppoe_softc_list (((struct ww_pppoe_state *)wwLwipModuleState(kWwLwipState_pppoe))->v_pppoe_softc_list)
#endif
]=])
    file(READ "${lwip_dir}/src/netif/ppp/pppoe.c" content)
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])pppoe_softc_list([^A-Za-z0-9_]|$)" "\\1ww_ctx_pppoe_softc_list\\2" content "${content}")
    string(REGEX REPLACE "(^|[^A-Za-z0-9_])pppoe_softc_list([^A-Za-z0-9_]|$)" "\\1ww_ctx_pppoe_softc_list\\2" content "${content}")
    string(REPLACE "->ww_ctx_pppoe_softc_list" "->pppoe_softc_list" content "${content}")
    string(REPLACE ".ww_ctx_pppoe_softc_list" ".pppoe_softc_list" content "${content}")
    file(WRITE "${lwip_dir}/src/netif/ppp/pppoe.c" "${content}")
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/ip4_addr.c"
[=[static char str[IP4ADDR_STRLEN_MAX];]=]
[=[static WW_LWIP_THREAD_LOCAL char str[IP4ADDR_STRLEN_MAX];]=])
    ww_lwip_replace_once("${lwip_dir}/src/netif/ppp/eui64.c"
[=[static char buf[20];]=]
[=[static WW_LWIP_THREAD_LOCAL char buf[20];]=])
    ww_lwip_replace_once("${lwip_dir}/src/netif/ppp/ipv6cp.c"
[=[static char b[26];]=]
[=[static WW_LWIP_THREAD_LOCAL char b[26];]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/ip6_addr.c"
[=[static char str[40];]=]
[=[static WW_LWIP_THREAD_LOCAL char str[40];]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/stats.c"
[=[struct stats_ lwip_stats;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
struct stats_ lwip_stats;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/stats.h"
[=[extern struct stats_ lwip_stats;]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct stats_ *wwLwipEngineStats(void);
#define lwip_stats (*wwLwipEngineStats())
#else
extern struct stats_ lwip_stats;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/init.c"
[=[  mem_init();
  memp_init();]=]
[=[#if !WW_LWIP_WORKER_ENGINES
  mem_init();
  memp_init();
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/init.c"
[=[#if PPP_SUPPORT
  ppp_init();]=]
[=[#if PPP_SUPPORT && !WW_LWIP_WORKER_ENGINES
  ppp_init();]=])
    ww_lwip_replace_once("${lwip_dir}/src/netif/ppp/ppp.c"
[=[  magic_init();]=]
[=[#if !WW_LWIP_WORKER_ENGINES
  magic_init();
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/timeouts.c"
[=[memp_malloc(MEMP_SYS_TIMEOUT)]=]
[=[wwLwipTimeoutAlloc()]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/timeouts.c"
[=[memp_free(MEMP_SYS_TIMEOUT, t)]=]
[=[wwLwipTimeoutFree(t)]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/timeouts.c"
[=[memp_free(MEMP_SYS_TIMEOUT, tmptimeout)]=]
[=[wwLwipTimeoutFree(tmptimeout)]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/timeouts.c"
[=[#include "lwip/memp.h"]=]
[=[#include "lwip/memp.h"
#if WW_LWIP_WORKER_ENGINES
#include "engine_internal.h"
#else
#define wwLwipTimeoutAlloc() memp_malloc(MEMP_SYS_TIMEOUT)
#define wwLwipTimeoutFree(p) memp_free(MEMP_SYS_TIMEOUT, (p))
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/netif.h"
[=[  u32_t ww_generation;]=]
[=[  u32_t ww_generation;
#if WW_LWIP_WORKER_ENGINES
  void *ww_engine;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[  netif->ww_generation = 0;]=]
[=[  netif->ww_generation = 0;
#if WW_LWIP_WORKER_ENGINES
  netif->ww_engine = wwLwipEngineCurrent();
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/ip.h"
[=[#define IP_PCB                             \]=]
[=[#if WW_LWIP_WORKER_ENGINES
#define WW_LWIP_IP_OWNER void *ww_engine;
#else
#define WW_LWIP_IP_OWNER
#endif
#define IP_PCB                             \
  WW_LWIP_IP_OWNER \]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[    memset(pcb, 0, sizeof(struct tcp_pcb));]=]
[=[    memset(pcb, 0, sizeof(struct tcp_pcb));
#if WW_LWIP_WORKER_ENGINES
    pcb->ww_engine = wwLwipEngineCurrent();
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[    memset(pcb, 0, sizeof(struct udp_pcb));]=]
[=[    memset(pcb, 0, sizeof(struct udp_pcb));
#if WW_LWIP_WORKER_ENGINES
    pcb->ww_engine = wwLwipEngineCurrent();
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[  lpcb->netif_generation = pcb->netif_generation;]=]
[=[  lpcb->netif_generation = pcb->netif_generation;
#if WW_LWIP_WORKER_ENGINES
  lpcb->ww_engine = pcb->ww_engine;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_bind_netif(struct tcp_pcb *pcb, const struct netif *netif)
{]=]
[=[
tcp_bind_netif(struct tcp_pcb *pcb, const struct netif *netif)
{
#if WW_LWIP_WORKER_ENGINES
  if (pcb->ww_engine != wwLwipEngineCurrent() || (netif != NULL && !wwLwipEngineOwnsNetif(netif))) { return ERR_ARG; }
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[
udp_bind_netif(struct udp_pcb *pcb, const struct netif *netif)
{]=]
[=[
udp_bind_netif(struct udp_pcb *pcb, const struct netif *netif)
{
#if WW_LWIP_WORKER_ENGINES
  if (pcb->ww_engine != wwLwipEngineCurrent() || (netif != NULL && !wwLwipEngineOwnsNetif(netif))) { return ERR_ARG; }
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_free(struct tcp_pcb *pcb)
{]=]
[=[
tcp_free(struct tcp_pcb *pcb)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_free_listen(struct tcp_pcb *pcb)
{]=]
[=[
tcp_free_listen(struct tcp_pcb *pcb)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_backlog_delayed(struct tcp_pcb *pcb)
{]=]
[=[
tcp_backlog_delayed(struct tcp_pcb *pcb)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_backlog_accepted(struct tcp_pcb *pcb)
{]=]
[=[
tcp_backlog_accepted(struct tcp_pcb *pcb)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_close(struct tcp_pcb *pcb)
{]=]
[=[
tcp_close(struct tcp_pcb *pcb)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_shutdown(struct tcp_pcb *pcb, int shut_rx, int shut_tx)
{]=]
[=[
tcp_shutdown(struct tcp_pcb *pcb, int shut_rx, int shut_tx)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_abandon(struct tcp_pcb *pcb, int reset)
{]=]
[=[
tcp_abandon(struct tcp_pcb *pcb, int reset)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_abort(struct tcp_pcb *pcb)
{]=]
[=[
tcp_abort(struct tcp_pcb *pcb)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_bind(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{]=]
[=[
tcp_bind(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_listen_with_backlog_and_err(struct tcp_pcb *pcb, u8_t backlog, err_t *err)
{]=]
[=[
tcp_listen_with_backlog_and_err(struct tcp_pcb *pcb, u8_t backlog, err_t *err)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_recved(struct tcp_pcb *pcb, u16_t len)
{]=]
[=[
tcp_recved(struct tcp_pcb *pcb, u16_t len)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_connect(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port,
            tcp_connected_fn connected)
{]=]
[=[
tcp_connect(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port,
            tcp_connected_fn connected)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_setprio(struct tcp_pcb *pcb, u8_t prio)
{]=]
[=[
tcp_setprio(struct tcp_pcb *pcb, u8_t prio)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_arg(struct tcp_pcb *pcb, void *arg)
{]=]
[=[
tcp_arg(struct tcp_pcb *pcb, void *arg)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_recv(struct tcp_pcb *pcb, tcp_recv_fn recv)
{]=]
[=[
tcp_recv(struct tcp_pcb *pcb, tcp_recv_fn recv)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_sent(struct tcp_pcb *pcb, tcp_sent_fn sent)
{]=]
[=[
tcp_sent(struct tcp_pcb *pcb, tcp_sent_fn sent)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_err(struct tcp_pcb *pcb, tcp_err_fn err)
{]=]
[=[
tcp_err(struct tcp_pcb *pcb, tcp_err_fn err)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_accept(struct tcp_pcb *pcb, tcp_accept_fn accept)
{]=]
[=[
tcp_accept(struct tcp_pcb *pcb, tcp_accept_fn accept)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_poll(struct tcp_pcb *pcb, tcp_poll_fn poll, u8_t interval)
{]=]
[=[
tcp_poll(struct tcp_pcb *pcb, tcp_poll_fn poll, u8_t interval)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[
tcp_write(struct tcp_pcb *pcb, const void *arg, u16_t len, u8_t apiflags)
{]=]
[=[
tcp_write(struct tcp_pcb *pcb, const void *arg, u16_t len, u8_t apiflags)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[
tcp_output(struct tcp_pcb *pcb)
{]=]
[=[
tcp_output(struct tcp_pcb *pcb)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[
tcp_rexmit(struct tcp_pcb *pcb)
{]=]
[=[
tcp_rexmit(struct tcp_pcb *pcb)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[
tcp_rexmit_rto(struct tcp_pcb *pcb)
{]=]
[=[
tcp_rexmit_rto(struct tcp_pcb *pcb)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[
tcp_send_fin(struct tcp_pcb *pcb)
{]=]
[=[
tcp_send_fin(struct tcp_pcb *pcb)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[
udp_send(struct udp_pcb *pcb, struct pbuf *p)
{]=]
[=[
udp_send(struct udp_pcb *pcb, struct pbuf *p)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[
udp_sendfrom(struct udp_pcb *pcb, struct pbuf *p,
             const ip_addr_t *src_ip, u16_t src_port)
{]=]
[=[
udp_sendfrom(struct udp_pcb *pcb, struct pbuf *p,
             const ip_addr_t *src_ip, u16_t src_port)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[
udp_sendto_chksum(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst_ip,
                  u16_t dst_port, u8_t have_chksum, u16_t chksum)
{]=]
[=[
udp_sendto_chksum(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst_ip,
                  u16_t dst_port, u8_t have_chksum, u16_t chksum)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[
udp_sendto_if_chksum(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst_ip,
                     u16_t dst_port, struct netif *netif, u8_t have_chksum,
                     u16_t chksum)
{]=]
[=[
udp_sendto_if_chksum(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst_ip,
                     u16_t dst_port, struct netif *netif, u8_t have_chksum,
                     u16_t chksum)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[
udp_sendto_if_src_chksum(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst_ip,
                         u16_t dst_port, struct netif *netif, u8_t have_chksum,
                         u16_t chksum, const ip_addr_t *src_ip)
{]=]
[=[
udp_sendto_if_src_chksum(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst_ip,
                         u16_t dst_port, struct netif *netif, u8_t have_chksum,
                         u16_t chksum, const ip_addr_t *src_ip)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[
udp_bind(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{]=]
[=[
udp_bind(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[
udp_connect(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{]=]
[=[
udp_connect(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[
udp_disconnect(struct udp_pcb *pcb)
{]=]
[=[
udp_disconnect(struct udp_pcb *pcb)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[
udp_recv(struct udp_pcb *pcb, udp_recv_fn recv, void *recv_arg)
{]=]
[=[
udp_recv(struct udp_pcb *pcb, udp_recv_fn recv, void *recv_arg)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[
udp_remove(struct udp_pcb *pcb)
{]=]
[=[
udp_remove(struct udp_pcb *pcb)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[
netif_remove(struct netif *netif)
{]=]
[=[
netif_remove(struct netif *netif)
{
  WW_LWIP_ASSERT_NETIF_OWNER(netif);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[
netif_set_default(struct netif *netif)
{]=]
[=[
netif_set_default(struct netif *netif)
{
  WW_LWIP_ASSERT_NETIF_OWNER(netif);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[
netif_set_up(struct netif *netif)
{]=]
[=[
netif_set_up(struct netif *netif)
{
  WW_LWIP_ASSERT_NETIF_OWNER(netif);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[
netif_set_down(struct netif *netif)
{]=]
[=[
netif_set_down(struct netif *netif)
{
  WW_LWIP_ASSERT_NETIF_OWNER(netif);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[
netif_set_link_up(struct netif *netif)
{]=]
[=[
netif_set_link_up(struct netif *netif)
{
  WW_LWIP_ASSERT_NETIF_OWNER(netif);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[
netif_set_link_down(struct netif *netif)
{]=]
[=[
netif_set_link_down(struct netif *netif)
{
  WW_LWIP_ASSERT_NETIF_OWNER(netif);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[
netif_poll(struct netif *netif)
{]=]
[=[
netif_poll(struct netif *netif)
{
  WW_LWIP_ASSERT_NETIF_OWNER(netif);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[
netif_ww_mutation_begin(struct netif *netif)
{]=]
[=[
netif_ww_mutation_begin(struct netif *netif)
{
  WW_LWIP_ASSERT_NETIF_OWNER(netif);]=])
endfunction()
