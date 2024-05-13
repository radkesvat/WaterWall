#pragma once
#include "tunnel.h"
#include "types.h"

#define CSTATE_D(x)     ((reverse_server_con_state_t *) ((((x)->line->chains_state)[state->chain_index_d])))
#define CSTATE_U(x)     ((reverse_server_con_state_t *) ((((x)->line->chains_state)[state->chain_index_u])))
#define CSTATE_D_MUT(x) ((x)->line->chains_state)[state->chain_index_d]
#define CSTATE_U_MUT(x) ((x)->line->chains_state)[state->chain_index_u]

static void addConnectionU(thread_box_t *box, reverse_server_con_state_t *con)
{
    con->next             = box->u_cons_root.next;
    box->u_cons_root.next = con;
    con->prev             = &box->u_cons_root;
    if (con->next)
    {
        con->next->prev = con;
    }
    box->u_count += 1;
}
static void removeConnectionU(thread_box_t *box, reverse_server_con_state_t *con)
{
    con->prev->next = con->next;
    if (con->next)
    {
        con->next->prev = con->prev;
    }
    box->u_count -= 1;
}

static void addConnectionD(thread_box_t *box, reverse_server_con_state_t *con)
{
    con->next             = box->d_cons_root.next;
    box->d_cons_root.next = con;
    con->prev             = &box->d_cons_root;
    if (con->next)
    {
        con->next->prev = con;
    }
    box->d_count += 1;
}
static void removeConnectionD(thread_box_t *box, reverse_server_con_state_t *con)
{
    con->prev->next = con->next;
    if (con->next)
    {
        con->next->prev = con->prev;
    }
    box->d_count -= 1;
}
static void onLinePausedU(void *cstate)
{
    pauseLineDownSide(((reverse_server_con_state_t *) cstate)->d);
}

static void onLineResumedU(void *cstate)
{
    resumeLineDownSide(((reverse_server_con_state_t *) cstate)->d);
}
static void onLinePausedD(void *cstate)
{
    pauseLineDownSide(((reverse_server_con_state_t *) cstate)->u);
}

static void onLineResumedD(void *cstate)
{
    resumeLineDownSide(((reverse_server_con_state_t *) cstate)->u);
}

static reverse_server_con_state_t *createCstate(bool isup, line_t *line)
{
    reverse_server_con_state_t *cstate = malloc(sizeof(reverse_server_con_state_t));
    memset(cstate, 0, sizeof(reverse_server_con_state_t));
    if (isup)
    {
        cstate->u      = line;
        cstate->uqueue = newContextQueue(getLineBufferPool(line));
    }
    else
    {
        cstate->d = line;
    }
    return cstate;
}

static void cleanup(reverse_server_con_state_t *cstate)
{

    if (cstate->uqueue)
    {
        destroyContextQueue(cstate->uqueue);
    }
    free(cstate);
}
