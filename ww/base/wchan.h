#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// wchan_t is an optionally-buffered messaging channel for CSP-like processing.
// Example:
//
//   wchan_t* c = wchannel_open(mem, sizeof(int), 4);
//
//   int send_messages[] = { 123, 456 };
//   chanSend(c, &send_messages[0]);
//   chanSend(c, &send_messages[1]);
//
//   int recv_messages[] = { 0, 0 };
//   chanRecv(c, &recv_messages[0]);
//   chanRecv(c, &recv_messages[1]);
//
//   assert(recv_messages[0] == send_messages[0]);
//   assert(recv_messages[1] == send_messages[1]);
//
//   wchan_close(c);
//   wchan_free(c);
//
typedef struct wchan_s wchan_t; // opaque

// chan_open creates and initializes a new channel which holds elements of elemsize byte.
// If bufcap>0 then a buffered channel with the capacity to hold bufcap elements is created.
wchan_t* chanOpen(size_t elemsize, uint32_t bufcap);

// chanClose cancels any waiting senders and receivers.
// Messages sent before this call are guaranteed to be delivered, assuming there are
// active receivers. Once a channel is closed it can not be reopened nor sent to.
// wchan_close must only be called once per channel.
void chanClose(wchan_t*);

// chanFree frees memory of a channel
void chanFree(wchan_t*);

// chanCap returns the channel's buffer capacity
uint32_t chanCap(const wchan_t* c);

// chanSend enqueues a message to a channel by copying the value at elemptr to the channel.
// Blocks until the message is sent or the channel is closed.
// Returns false if the channel closed.
bool chanSend(wchan_t*, void* elemptr);

// chanRecv dequeues a message from a channel by copying a received value to elemptr.
// Blocks until there's a message available or the channel is closed.
// Returns true if a message was received, false if the channel is closed.
bool chanRecv(wchan_t*, void* elemptr);

// chanTrySend attempts to sends a message without blocking.
// It returns true if the message was sent, false if not.
// Unlike chanSend, this function does not return false to indicate that the channel
// is closed, but instead it returns false if the message was not sent and sets *closed
// to false if the reason for the failure was a closed channel.
bool chanTrySend(wchan_t*, void* elemptr, bool* closed);

// chanTryRecv works like chanRecv but does not block.
// Returns true if a message was received.
// This function does not block/wait.
bool chanTryRecv(wchan_t* ch, void* elemptr, bool* closed);
