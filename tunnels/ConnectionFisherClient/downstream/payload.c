#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherclientHandleChildHandshakePayload(tunnel_t *t, line_t *child_l, sbuf_t *buf);

void connectionfisherclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    connectionfisherclient_lstate_t *ls = lineGetState(l, t);

    if (ls->role != kConnectionFisherClientRoleChild)
    {
        LOGW("ConnectionFisherClient: unexpected downstream payload on the main line");
        lineReuseBuffer(l, buf);
        if (ls->role == kConnectionFisherClientRoleMain)
        {
            connectionfisherclientCloseMainLine(t, l);
        }
        return;
    }

    if (! ls->child_handshake_complete)
    {
        connectionfisherclientHandleChildHandshakePayload(t, l, buf);
        return;
    }

    if (ls->main_line == NULL || ! lineIsAlive(ls->main_line))
    {
        lineReuseBuffer(l, buf);
        connectionfisherclientCloseChildLine(t, l, false);
        return;
    }

    connectionfisherclient_lstate_t *main_ls = lineGetState(ls->main_line, t);
    if (main_ls->role != kConnectionFisherClientRoleMain || main_ls->selected_child != l)
    {
        lineReuseBuffer(l, buf);
        connectionfisherclientCloseChildLine(t, l, false);
        return;
    }

    discard withLineLockedWithBuf(ls->main_line, tunnelPrevDownStreamPayload, t, buf);
}
