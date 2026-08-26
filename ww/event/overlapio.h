#ifndef WW_OVERLAPPED_H_
#define WW_OVERLAPPED_H_

#include "iowatcher.h"

#ifdef EVENT_IOCP

#include "hbuf.h"
#include "wsocket.h"
#include <mswsock.h>
#ifdef _MSC_VER
#pragma comment(lib, "mswsock.lib")
#endif

// Kind of overlapped operation. Dispatch and retire consult record->kind so a
// completion no longer needs a singleton io->hovlp to know what it was.
typedef enum woverlapped_kind_e
{
    WOVERLAPPED_ACCEPT,
    WOVERLAPPED_CONNECT,
    WOVERLAPPED_RECV,
    WOVERLAPPED_SEND,
} woverlapped_kind_e;

// Why a record was canceled. A canceled record must never invoke a user callback
// even if its completion reports success, because the kernel may have completed
// it just before the cancel took effect.
typedef enum woverlapped_cancel_reason_e
{
    WOVERLAPPED_NOT_CANCELED,
    WOVERLAPPED_CANCEL_STOP,     // wioReadStop/write stop: socket stays open
    WOVERLAPPED_CANCEL_CLOSE,    // wioClose: socket is closing
    WOVERLAPPED_CANCEL_SHUTDOWN, // loop destruction
} woverlapped_cancel_reason_e;

typedef struct woverlapped_s
{
    OVERLAPPED ovlp; // Must remain first: GetQueuedCompletionStatus returns &ovlp.

    wio_t                      *io;
    uint32_t                    io_id; // io->id captured at attach; stale-generation guard
    woverlapped_kind_e          kind;
    woverlapped_cancel_reason_e cancel_reason;

    struct woverlapped_s *posted_prev; // doubly linked posted-operation list
    struct woverlapped_s *posted_next;
    struct woverlapped_s *completed_next; // singly linked completed FIFO

    bool posted;    // currently owned by the kernel (in io->iocp_posted_*)
    bool completed; // dequeued from the kernel (in io->iocp_completed_*)

    int     fd;          // provisional accepted socket (accept), else the owning io fd
    WSABUF  buf;         // recv: points into sbuf; send/accept: record-owned raw buffer
    sbuf_t *sbuf;        // recv only: detached to read_cb on a successful receive
    char   *send_buffer; // send only: allocation base (buf.buf advances on partial completion)
    DWORD   bytes;
    int     error;

    // recvfrom peer address scratch (UDP/raw receive)
    struct sockaddr *addr;
    int              addrlen;

    // AcceptEx sizing, computed per listener family (Phase 5).
    int   accept_family;         // AF_INET or AF_INET6 the buffer was built for
    DWORD accept_address_length; // one sockaddr region: sockaddr len + 16
    DWORD accept_buffer_length;  // total AcceptEx output buffer: 2 * region
} woverlapped_t;

_Static_assert(offsetof(woverlapped_t, ovlp) == 0,
               "OVERLAPPED must be the first member so a completed LPOVERLAPPED casts back to woverlapped_t");

// --- iocp.c <-> overlapio.c completion plumbing ---------------------------------

// Move a record the kernel just returned from the posted list to the completed
// queue, recording its byte count and error (0 on success).
void wioIocpOnDequeued(woverlapped_t *record, DWORD bytes, int error);

// Retire every already-dequeued completion for a closed/inactive io without
// invoking user callbacks. May finalize a deferred wio_t once its last record is
// released; the caller must not touch io afterwards.
void wioIocpRetireCompletedWithoutCallbacks(wio_t *io);

// Record-aware cancellation. Marks matching posted records and issues CancelIoEx.
// Records are not freed here; their completion packets still arrive and retire
// them. Only records not already canceled are (re)marked, so the first reason
// (e.g. CLOSE) wins over a later STOP from wioDel.
void wioIocpCancel(wio_t *io, int event_mask, woverlapped_cancel_reason_e reason);

// True once a deferred-finalized wio_t has no remaining kernel references.
bool wioIocpCanFinalize(wio_t *io);

// Finalize a deferred wio_t if its pending-loop cursor and all operation records
// have released it. May return io to its pool; callers must not touch io after.
void wioIocpFinalizeDeferred(wio_t *io);

#if defined(WATERWALL_IOCP_TEST_HOOKS)
// --- test-only AcceptEx fault injection ----------------------------------------
// Make the next `count` AcceptEx submissions fail immediately with `error`
// (0 selects WSAENOBUFS), exercising the same unpost/retire path as a real
// immediate failure. Arm this only after listener startup so the initial slots
// are real. Never compiled into production builds.
void     wioIocpTestForceAcceptExFailures(uint32_t count, int error);
uint32_t wioIocpTestPendingAcceptExFailures(void);
void     wioIocpTestSetAfterDirectSendHook(void (*hook)(wio_t *io));
#endif

#endif

#endif // WW_OVERLAPPED_H_
