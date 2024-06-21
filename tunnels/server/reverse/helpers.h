#pragma once
#include "hatomic.h"
#include "tunnel.h"
#include "types.h"

static void addConnectionU(thread_box_t *box, reverse_server_con_state_t *con)
{
    con->next             = box->u_cons_root.next;
    box->u_cons_root.next = con;
    con->prev             = &box->u_cons_root;
    if (con->next)
    {
        con->next->prev = con;
    }
    atomic_fetch_add_explicit(&(box->u_count), 1, memory_order_relaxed);
}
static void removeConnectionU(thread_box_t *box, reverse_server_con_state_t *con)
{
    con->prev->next = con->next;
    if (con->next)
    {
        con->next->prev = con->prev;
    }
    atomic_fetch_add_explicit(&(box->u_count), -1, memory_order_relaxed);
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
static void onLinePausedU(void *userdata)
{
    reverse_server_con_state_t *cstate = (reverse_server_con_state_t *) userdata;
    if (cstate->paired)
    {
        pauseLineDownSide(cstate->d);
    }
}

static void onLineResumedU(void *userdata)
{
    reverse_server_con_state_t *cstate = (reverse_server_con_state_t *) userdata;
    if (cstate->paired)
    {
        resumeLineDownSide(cstate->d);
    }
}
static void onLinePausedD(void *userdata)
{
    reverse_server_con_state_t *cstate = (reverse_server_con_state_t *) userdata;
    if (cstate->paired)
    {
        pauseLineDownSide(cstate->u);
    }
}

static void onLineResumedD(void *userdata)
{
    reverse_server_con_state_t *cstate = (reverse_server_con_state_t *) userdata;
    if (cstate->paired)
    {
        resumeLineDownSide(cstate->u);
    }
}

static reverse_server_con_state_t *createCstateU(line_t *line)
{
    reverse_server_con_state_t *cstate = malloc(sizeof(reverse_server_con_state_t));
    memset(cstate, 0, sizeof(reverse_server_con_state_t));
    cstate->u      = line;
    cstate->uqueue = newContextQueue(getLineBufferPool(line));
    setupLineUpSide(line, onLinePausedU, cstate, onLineResumedU);
    return cstate;
}

static reverse_server_con_state_t *createCstateD(line_t *line)
{
    reverse_server_con_state_t *cstate = malloc(sizeof(reverse_server_con_state_t));
    memset(cstate, 0, sizeof(reverse_server_con_state_t));
    cstate->wait_stream = newBufferStream(getLineBufferPool(line));
    cstate->d           = line;
    setupLineUpSide(line, onLinePausedD, cstate, onLineResumedD);

    return cstate;
}

static void cleanup(reverse_server_con_state_t *cstate)
{
    // since the connection could be in any state, and i did not want to use much memory to cover all cases
    // so protect everything with if
    if (cstate->uqueue)
    {
        destroyContextQueue(cstate->uqueue);
    }
    if (cstate->wait_stream)
    {
        destroyBufferStream(cstate->wait_stream);
    }
    if (cstate->d)
    {
        doneLineUpSide(cstate->d);
    }
    if (cstate->u)
    {
        doneLineUpSide(cstate->u);
    }

    free(cstate);
}
