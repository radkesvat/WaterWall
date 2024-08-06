#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// hchan_t is an optionally-buffered messaging channel for CSP-like processing.
// Example:
//
//   hchan_t* c = hchannel_open(mem, sizeof(int), 4);
//
//   int send_messages[] = { 123, 456 };
//   hchan_send(c, &send_messages[0]);
//   hchan_send(c, &send_messages[1]);
//
//   int recv_messages[] = { 0, 0 };
//   hchan_recv(c, &recv_messages[0]);
//   hchan_recv(c, &recv_messages[1]);
//
//   assert(recv_messages[0] == send_messages[0]);
//   assert(recv_messages[1] == send_messages[1]);
//
//   hchan_close(c);
//   hchan_free(c);
//
typedef struct hchan_s hchan_t; // opaque

// hchan_open creates and initializes a new channel which holds elements of elemsize byte.
// If bufcap>0 then a buffered channel with the capacity to hold bufcap elements is created.
hchan_t* hchanOpen(size_t elemsize, uint32_t bufcap);

// hchan_close cancels any waiting senders and receivers.
// Messages sent before this call are guaranteed to be delivered, assuming there are
// active receivers. Once a channel is closed it can not be reopened nor sent to.
// hchan_close must only be called once per channel.
void hchanClose(hchan_t*);

// hchan_free frees memory of a channel
void hchanFree(hchan_t*);

// hchan_cap returns the channel's buffer capacity
uint32_t hchanCap(const hchan_t* c);

// hchan_send enqueues a message to a channel by copying the value at elemptr to the channel.
// Blocks until the message is sent or the channel is closed.
// Returns false if the channel closed.
bool hchanSend(hchan_t*, void* elemptr);

// hchan_recv dequeues a message from a channel by copying a received value to elemptr.
// Blocks until there's a message available or the channel is closed.
// Returns true if a message was received, false if the channel is closed.
bool hchanRecv(hchan_t*, void* elemptr);

// hchan_trysend attempts to sends a message without blocking.
// It returns true if the message was sent, false if not.
// Unlike hchan_send, this function does not return false to indicate that the channel
// is closed, but instead it returns false if the message was not sent and sets *closed
// to false if the reason for the failure was a closed channel.
bool hchanTrySend(hchan_t*, void* elemptr, bool* closed);

// hchan_tryrecv works like hchan_recv but does not block.
// Returns true if a message was received.
// This function does not block/wait.
bool hchanTryRecv(hchan_t* ch, void* elemptr, bool* closed);
