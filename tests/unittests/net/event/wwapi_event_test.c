/* Exercise the event API from the header a node includes. */
#include "wwapi.h"

#ifdef WW_EVENT_H_
#error "wwapi.h exposes private event layouts"
#endif

static unsigned closes;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(EXIT_FAILURE);
    }
}

static void onClose(wio_t *io)
{
    require(wioGetContext(io) == &closes && wioGetError(io) == ETIMEDOUT, "socket lost its context or close error");
    ++closes;
}

static void unexpectedEvent(wevent_t *event)
{
    discard event;
    require(false, "replaced callback survived");
}

static void onTimer(wtimer_t *timer)
{
    wloop_t *loop = weventGetLoop(timer);
    require(loop == getCurrentWorkerLoop() && weventGetUserdata(timer) == &closes, "timer lost its owner or userdata");
    require(weventGetId(timer) == 42 && weventGetPriority(timer) == WEVENT_HIGH_PRIORITY,
            "timer lost its id or priority");
    wio_t *io = wioCreateSocket(loop, "127.0.0.1", 0, WIO_TYPE_UDP, WIO_CLIENT_SIDE);
    require(io != NULL && wioIsOpened(io), "could not create UDP handle");
    wioSetContext(io, &closes);
    wioSetCallBackClose(io, onClose);
    require(wioCloseWithError(io, ETIMEDOUT) == 0 && closes == 1, "socket close callback did not run exactly once");
    wioFree(io);
    require(requestProgramShutdown(0), "shutdown request refused");
}

int main(void)
{
    static char            off[] = "OFF";
    ww_construction_data_t data  = {
         .workers_count                  = 1,
         .ram_profile                    = kRamProfileS2Memory,
         .mtu_size                       = 1500,
         .internal_logger_data.log_level = off,
         .core_logger_data.log_level     = off,
         .network_logger_data.log_level  = off,
         .dns_logger_data.log_level      = off,
    };
    require(wwStartupSucceeded(createGlobalState(data)), "could not initialize worker");
    wtimer_t *timer = wtimerAddDeadline(getCurrentWorkerLoop(), onTimer, 1);
    require(timer != NULL && weventGetEventType(timer) == WEVENT_TYPE_TIMEOUT, "could not arm timeout");
    wevent_cb original = weventGetCallBack(timer);
    weventSetCallBack(timer, unexpectedEvent);
    require(weventGetCallBack(timer) == unexpectedEvent, "named callback was not installed");
    weventSetCallBack(timer, original);
    weventSetID(timer, 42);
    weventSetPriority(timer, WEVENT_HIGH_PRIORITY);
    weventSetUserData(timer, &closes);
    runMainThread();
    return EXIT_FAILURE;
}
