#ifndef HV_BUF_H_
#define HV_BUF_H_

#include "hdef.h"   // for MAX
#include "hbase.h"  // for HV_ALLOC, HV_FREE

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


#endif // HV_BUF_H_
