#ifndef WW_BASE_H_
#define WW_BASE_H_

#include "wlibc.h"


//--------------------alloc/free---------------------------



WW_EXPORT void* eventloopMalloc(size_t size);
WW_EXPORT void* eventloopRealloc(void* oldptr, size_t newsize, size_t oldsize);
WW_EXPORT void* eventloopCalloc(size_t nmemb, size_t size);
WW_EXPORT void* eventloopZalloc(size_t size);
WW_EXPORT void  eventloopFree(void* ptr);

#define EVENTLOOP_ALLOC(ptr, size)\
    do {\
        *(void**)&(ptr) = eventloopZalloc(size);\
        printd("alloc(%p, size=%llu)\tat [%s:%d:%s]\n", ptr, (unsigned long long)size, __FILE__, __LINE__, __FUNCTION__);\
    } while(0)

#define EVENTLOOP_ALLOC_SIZEOF(ptr)  EVENTLOOP_ALLOC(ptr, sizeof(*(ptr)))

#define EVENTLOOP_FREE(ptr)\
    do {\
        if (ptr) {\
            eventloopFree(ptr);\
            printd("memoryFree( %p )\tat [%s:%d:%s]\n", ptr, __FILE__, __LINE__, __FUNCTION__);\
            ptr = NULL;\
        }\
    } while(0)

#define STACK_OR_HEAP_ALLOC(ptr, size, stack_size)\
    unsigned char _stackbuf_[stack_size] = { 0 };\
    if ((size) > (stack_size)) {\
        EVENTLOOP_ALLOC(ptr, size);\
    } else {\
        *(unsigned char**)&(ptr) = _stackbuf_;\
    }

#define STACK_OR_HEAP_FREE(ptr)\
    if ((unsigned char*)(ptr) != _stackbuf_) {\
        EVENTLOOP_FREE(ptr);\
    }

#define WW_DEFAULT_STACKBUF_SIZE    1024
#define WW_STACK_ALLOC(ptr, size)   STACK_OR_HEAP_ALLOC(ptr, size, WW_DEFAULT_STACKBUF_SIZE)
#define WW_STACK_FREE(ptr)          STACK_OR_HEAP_FREE(ptr)

WW_EXPORT long eventloopAllocCount(void);
WW_EXPORT long eventloopFreeCount(void);



WW_INLINE void wwMemCheck(void)
{
    printf("Memcheck => alloc:%ld free:%ld\n", eventloopAllocCount(), eventloopFreeCount());
}
#define EV_MEMCHECK atexit(wwMemCheck);


#endif // WW_BASE_H_
