#pragma once
#include "types.h"


#define STATE(x) ((reverse_server_state_t *)((x)->state))
#define CSTATE_D(x) ((reverse_server_con_state_t *)((((x)->line->chains_state)[state->chain_index_d])))
#define CSTATE_U(x) ((reverse_server_con_state_t *)((((x)->line->chains_state)[state->chain_index_u])))
#define CSTATE_D_MUT(x) ((x)->line->chains_state)[state->chain_index_d]
#define CSTATE_U_MUT(x) ((x)->line->chains_state)[state->chain_index_u]
#define ISALIVE(x) (CSTATE(x) != NULL)


static reverse_server_con_state_t *create_cstate(bool isup, line_t *line)
{
    reverse_server_con_state_t *cstate = malloc(sizeof(reverse_server_con_state_t));
    memset(cstate, 0, sizeof(reverse_server_con_state_t));
    if (isup)
    {
        cstate->u = line;
        cstate->uqueue = newContextQueue(buffer_pools[line->tid]);
    }
    else
    {
        cstate->d = line;
    }
    return cstate;
}

static void destroy_cstate(reverse_server_con_state_t *cstate)
{

    if (cstate->uqueue)
        destroyContextQueue(cstate->uqueue);
    free(cstate);
}

