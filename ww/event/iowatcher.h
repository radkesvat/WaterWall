#ifndef IO_WATCHER_H_
#define IO_WATCHER_H_

#include "wloop.h"

#include "wplatform.h"
#if !defined(EVENT_SELECT) &&   \
    !defined(EVENT_POLL) &&     \
    !defined(EVENT_EPOLL) &&    \
    !defined(EVENT_KQUEUE) &&   \
    !defined(EVENT_IOCP) &&     \
    !defined(EVENT_PORT) &&     \
    !defined(EVENT_NOEVENT)
#ifdef OS_WIN
  #if WITH_WEPOLL
    #define EVENT_EPOLL // wepoll -> iocp
  #else
    #define EVENT_POLL  // WSAPoll
  #endif
#elif defined(OS_LINUX)
#define EVENT_EPOLL
#elif defined(OS_MAC)
#define EVENT_KQUEUE
#elif defined(OS_BSD)
#define EVENT_KQUEUE
#elif defined(OS_SOLARIS)
#define EVENT_PORT
#else
#define EVENT_SELECT
#endif
#endif

int iowatcherInit(wloop_t* loop);
int iowatcherCleanUp(wloop_t* loop);
int iowatcherAddEvent(wloop_t* loop, int fd, int events);
int iowatcherDelEvent(wloop_t* loop, int fd, int events);
int iowatcherPollEvents(wloop_t* loop, int timeout);

#endif
