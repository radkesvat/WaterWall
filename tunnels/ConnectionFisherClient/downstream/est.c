#include "structure.h"

void connectionfisherclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    connectionfisherclient_lstate_t *ls = lineGetState(l, t);
    if (ls->role != kConnectionFisherClientRoleChild)
        return;
    if (! lineIsEstablished(l))
        lineMarkEstablished(l);
    line_t *main_l = ls->main_line;
    if (main_l == NULL || ! lineIsAlive(main_l))
        return;
    connectionfisherclient_lstate_t *main_ls = lineGetState(main_l, t);
    if (main_ls->role != kConnectionFisherClientRoleMain || main_ls->main_est_forwarded ||
        ls->child_slot >= main_ls->child_count || main_ls->child_lines[ls->child_slot] != l ||
        (main_ls->selected_child != NULL && main_ls->selected_child != l))
        return;
    main_ls->main_est_forwarded = true;
    if (! lineIsEstablished(main_l))
        lineMarkEstablished(main_l);
    lineRef(l);
    lineRef(main_l);
    tunnelPrevDownStreamEst(t, main_l);
    lineUnref(main_l);
    lineUnref(l);
}
