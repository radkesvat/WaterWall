#ifndef WW_BUF_H_
#define WW_BUF_H_

#include "wdef.h"   // for MAX
#include "ev_memory.h"  // for EVENTLOOP_ALLOC, EVENTLOOP_FREE

typedef struct hbuf_s {
    char*  base;
    size_t len;

} hbuf_t;

typedef struct offset_buf_s {
    char*   base;
    size_t  len;
    size_t  offset;

} offset_buf_t;

typedef struct fifo_buf_s {
    char*  base;
    size_t len;
    size_t head;
    size_t tail;

} fifo_buf_t;


#endif // WW_BUF_H_
