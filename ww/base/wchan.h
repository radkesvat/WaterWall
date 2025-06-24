#ifndef chan_h
#define chan_h

#include "wlibc.h"

#include "chan_queue.h"

// Defines a thread-safe communication pipe. Channels are either buffered or
// unbuffered. An unbuffered channel is synchronized. Receiving on either type
// of channel will block until there is data to receive. If the channel is
// unbuffered, the sender blocks until the receiver has received the value. If
// the channel is buffered, the sender only blocks until the value has been
// copied to the buffer, meaning it will block if the channel is full.
typedef struct wchan_s
{
    // Buffered channel properties
    queue_t *queue;

    // Unbuffered channel properties
    wmutex_t r_mu;
    wmutex_t w_mu;
    void    *data;

    // Shared properties
    wmutex_t   m_mu;
    wcondvar_t r_cond;
    wcondvar_t w_cond;
    int        closed;
    int        r_waiting;
    int        w_waiting;
} wchan_t;

// Allocates and returns a new channel. The capacity specifies whether the
// channel should be buffered or not. A capacity of 0 will create an unbuffered
// channel. Sets errno and returns NULL if initialization failed.
wchan_t *chanInit(size_t capacity);

// Releases the channel resources.
void chanDispose(wchan_t *chan);

// Once a channel is closed, data cannot be sent into it. If the channel is
// buffered, data can be read from it until it is empty, after which reads will
// return an error code. Reading from a closed channel that is unbuffered will
// return an error code. Closing a channel does not release its resources. This
// must be done with a call to chanDispose. Returns 0 if the channel was
// successfully closed, -1 otherwise.
int chanClose(wchan_t *chan);

// Returns 0 if the channel is open and 1 if it is closed.
int chanIsClosed(wchan_t *chan);

// Sends a value into the channel. If the channel is unbuffered, this will
// block until a receiver receives the value. If the channel is buffered and at
// capacity, this will block until a receiver receives a value. Returns 0 if
// the send succeeded or -1 if it failed.
int chanSend(wchan_t *chan, void *data);

// Receives a value from the channel. This will block until there is data to
// receive. Returns 0 if the receive succeeded or -1 if it failed.
int chanRecv(wchan_t *chan, void **data);

// Returns the number of items in the channel buffer. If the channel is
// unbuffered, this will return 0.
int chanSize(wchan_t *chan);

// A select statement chooses which of a set of possible send or receive
// operations will proceed. The return value indicates which channel's
// operation has proceeded. If more than one operation can proceed, one is
// selected randomly. If none can proceed, -1 is returned. Select is intended
// to be used in conjunction with a switch statement. In the case of a receive
// operation, the received value will be pointed to by the provided pointer. In
// the case of a send, the value at the same index as the channel will be sent.
int chanSelect(wchan_t *recvChans[], int recvCount, void **recvOut, wchan_t *sendChans[], int sendCount,
               void *sendMsgs[]);

// Typed interface to send/recv chan.
int chanSendInt32(wchan_t *, int32_t);
int chanSendInt64(wchan_t *, int64_t);
#if ULONG_MAX == 4294967295UL
#define chanSendInt(c, d) chanSendInt64(c, d)
#else
#define chanSendInt(c, d) chanSendInt32(c, d)
#endif
int chanSendDouble(wchan_t *, double);
int chanSendBuf(wchan_t *, void *, size_t);
int chanRecvInt32(wchan_t *, int32_t *);
int chanRecvInt64(wchan_t *, int64_t *);
#if ULONG_MAX == 4294967295UL
#define chanRecvInt(c, d) chanRecvInt64(c, d)
#else
#define chanRecvInt(c, d) chanRecvInt32(c, d)
#endif
int chanRecvDouble(wchan_t *, double *);
int chanRecvBuf(wchan_t *, void *, size_t);

#endif
