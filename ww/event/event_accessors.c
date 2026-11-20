#include "wevent.h"

void weventSetID(void *event, uint64_t id)
{
    ((wevent_t *) event)->event_id = id;
}

void weventSetCallBack(void *event, wevent_cb callback)
{
    ((wevent_t *) event)->cb = callback;
}

void weventSetPriority(void *event, int priority)
{
    assert(priority >= WEVENT_LOWEST_PRIORITY && priority <= WEVENT_HIGHEST_PRIORITY);
    ((wevent_t *) event)->priority = priority;
}

void weventSetUserData(void *event, void *userdata)
{
    ((wevent_t *) event)->userdata = userdata;
}

wloop_t *weventGetLoop(const void *event)
{
    return ((const wevent_t *) event)->loop;
}

wevent_type_e weventGetEventType(const void *event)
{
    return ((const wevent_t *) event)->event_type;
}

uint64_t weventGetId(const void *event)
{
    return ((const wevent_t *) event)->event_id;
}

wevent_cb weventGetCallBack(const void *event)
{
    return ((const wevent_t *) event)->cb;
}

int weventGetPriority(const void *event)
{
    return ((const wevent_t *) event)->priority;
}

void *weventGetUserdata(const void *event)
{
    return ((const wevent_t *) event)->userdata;
}
