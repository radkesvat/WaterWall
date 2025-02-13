#include "iowatcher.h"

#ifdef EVENT_NOEVENT
int iowatcherInit(wloop_t* loop) {
    return 0;
}

int iowatcherCleanUp(wloop_t* loop) {
    return 0;
}

int iowatcherAddEvent(wloop_t* loop, int fd, int events) {
    return 0;
}

int iowatcherDelEvent(wloop_t* loop, int fd, int events) {
    return 0;
}

int iowatcherPollEvents(wloop_t* loop, int timeout) {
    ww_delay(timeout);
    return 0;
}

#endif
