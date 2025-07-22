#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverAddConnectionU(reverseserver_thread_box_t *box, reverseserver_lstate_t *con)
{
    con->next   = box->u_root;
    con->prev   = NULL;  // New head has no previous node
    if (box->u_root)
    {
        box->u_root->prev = con;
    }
    box->u_root = con;
    box->u_count += 1;
}
void reverseserverRemoveConnectionU(reverseserver_thread_box_t *box, reverseserver_lstate_t *con)
{
    if (con->prev)
    {
        con->prev->next = con->next;
    }
    else
    {
        // con is the head, update root pointer
        box->u_root = con->next;
    }
    
    if (con->next)
    {
        con->next->prev = con->prev;
    }
    box->u_count -= 1;
}

void reverseserverAddConnectionD(reverseserver_thread_box_t *box, reverseserver_lstate_t *con)
{
    con->next   = box->d_root;
    con->prev   = NULL;  // New head has no previous node
    if (box->d_root)
    {
        box->d_root->prev = con;
    }
    box->d_root = con;
    box->d_count += 1;
}
void reverseserverRemoveConnectionD(reverseserver_thread_box_t *box, reverseserver_lstate_t *con)
{
    if (con->prev)
    {
        con->prev->next = con->next;
    }
    else
    {
        // con is the head, update root pointer
        box->d_root = con->next;
    }
    
    if (con->next)
    {
        con->next->prev = con->prev;
    }
    box->d_count -= 1;
}
