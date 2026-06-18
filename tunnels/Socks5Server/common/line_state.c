#include "structure.h"

#include "loggers/network_logger.h"

void socks5serverLinestateInitialize(socks5server_lstate_t *ls, tunnel_t *t, line_t *l, socks5server_line_kind_t kind)
{
    *ls = (socks5server_lstate_t) {
        .tunnel            = t,
        .line              = l,
        .in_stream         = bufferstreamCreate(lineGetBufferPool(l), 0),
        .pending_up        = bufferqueueCreate(kSocks5ServerBufferQueueCap),
        .pending_down      = bufferqueueCreate(kSocks5ServerBufferQueueCap),
        .udp_remote_lines  = socks5server_remote_map_t_with_capacity(kSocks5ServerRemoteMapCap),
        .client_line       = NULL,
        .user_handle       = userHandleEmpty(),
        .auth_username     = NULL,
        .auth_password     = NULL,
        .remote_key        = 0,
        .association_key   = 0,
        .association_token = 0,
        .phase = kind == kSocks5ServerLineKindControlTcp ? kSocks5ServerPhaseWaitMethod : kSocks5ServerPhaseIdle,
        .kind  = kind,
        .connect_reply_sent = false,
        .client_line_locked = false,
        .user_handle_recorded = false,
        .prev_finished      = false,
        .next_finished      = false};
}

void socks5serverLinestateDestroy(socks5server_lstate_t *ls)
{
    bufferstreamDestroy(&ls->in_stream);
    bufferqueueDestroy(&ls->pending_up);
    bufferqueueDestroy(&ls->pending_down);
    socks5server_remote_map_t_drop(&ls->udp_remote_lines);
    if (ls->auth_username != NULL)
    {
        memoryFree(ls->auth_username);
    }
    if (ls->auth_password != NULL)
    {
        memoryFree(ls->auth_password);
    }
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
