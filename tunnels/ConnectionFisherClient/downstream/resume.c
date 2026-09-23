#include "structure.h"

void connectionfisherclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    connectionfisherclient_lstate_t *ls = lineGetState(l, t);
    if (ls->role != kConnectionFisherClientRoleChild)
        return;
    ls->next_paused = false;
    line_t *main_l  = ls->main_line;
    if (main_l == NULL || ! lineIsAlive(main_l))
        return;
    lineRef(l);
    lineRef(main_l);
    if (! connectionfisherclientSendPing(t, l) || ! lineIsAlive(main_l) || ! lineIsAlive(l))
        goto done;
    connectionfisherclient_lstate_t *main_ls = lineGetState(main_l, t);
    if (main_ls->role != kConnectionFisherClientRoleMain || main_ls->selected_child != l)
        goto done;
    discard connectionfisherclientFlushPendingToSelected(t, main_l, l);
done:
    lineUnref(main_l);
    lineUnref(l);
}
