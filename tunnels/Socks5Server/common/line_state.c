#include "internal.h"

#include "loggers/network_logger.h"

void socks5serverLinestateInitialize(socks5server_lstate_t *ls, tunnel_t *t, line_t *l, socks5server_line_kind_t kind)
{
    if (kind == kSocks5ServerLineKindUdpClient || kind == kSocks5ServerLineKindUdpRemote)
    {
        linePreferOrdinaryReadBoth(l);
    }
    *ls = (socks5server_lstate_t) {
        .tunnel           = t,
        .line             = l,
        .in_stream        = kind == kSocks5ServerLineKindControlTcp
                                ? bufferstreamCreate(lineGetBufferPool(l), 0)
                                : (buffer_stream_t) {.pool = lineGetBufferPool(l), .q = bs_doublequeue_t_init()},
        .udp_remote_lines = socks5server_remote_map_t_init(),
        .client_line      = NULL,
        .user_handle      = userHandleEmpty(),
        .auth_username    = NULL,
        .auth_password    = NULL,
        .remote_key       = NULL,
        .dynamic_handle   = (udplistener_dynamic_endpoint_handle_t) {0},
        .phase = kind == kSocks5ServerLineKindControlTcp ? kSocks5ServerPhaseWaitMethod : kSocks5ServerPhaseIdle,
        .kind  = kind,
        .connect_reply_sent          = false,
        .client_line_ref_held        = false,
        .user_handle_recorded        = false,
        .udp_first_payload_validated = false,
        .prev_finished               = false,
        .next_finished               = false};
    bufferqueueInitEmpty(&ls->pending_up);
    bufferqueueInitEmpty(&ls->pending_down);
}

void socks5serverLinestateDestroy(socks5server_lstate_t *ls)
{
    bufferstreamDestroy(&ls->in_stream);
    bufferqueueDestroy(&ls->pending_up);
    bufferqueueDestroy(&ls->pending_down);
    socks5server_remote_map_t_drop(&ls->udp_remote_lines);
    memoryFree(ls->remote_key);
    if (ls->auth_username != NULL)
    {
        memoryFree(ls->auth_username);
        ls->auth_username = NULL;
    }
    if (ls->auth_password != NULL)
    {
        memoryFree(ls->auth_password);
        ls->auth_password = NULL;
    }
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
