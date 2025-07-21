#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverAddConnectionU(reverseserver_thread_box_t *box, reverseserver_lstate_t *con)
{
    con->next   = box->u_root;
    box->u_root = con;
    con->prev   = box->u_root;
    if (con->next)
    {
        con->next->prev = con;
    }
    box->u_count += 1;
}
void reverseserverRemoveConnectionU(reverseserver_thread_box_t *box, reverseserver_lstate_t *con)
{
    con->prev->next = con->next;
    if (con->next)
    {
        con->next->prev = con->prev;
    }
    box->u_count -= 1;
}

void reverseserverAddConnectionD(reverseserver_thread_box_t *box, reverseserver_lstate_t *con)
{
    con->next   = box->d_root;
    box->d_root = con;
    con->prev   = box->d_root;
    if (con->next)
    {
        con->next->prev = con;
    }
    box->d_count += 1;
}
void reverseserverRemoveConnectionD(reverseserver_thread_box_t *box, reverseserver_lstate_t *con)
{
    con->prev->next = con->next;
    if (con->next)
    {
        con->next->prev = con->prev;
    }
    box->d_count -= 1;
}
