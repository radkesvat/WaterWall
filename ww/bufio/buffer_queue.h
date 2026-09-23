/**
 * @file buffer_queue.h
 * @brief A FIFO queue implementation for managing sbuf_t buffers.
 */

#pragma once

#include "buffer_budget.h"
#include "context.h"
#include "tunnel.h"
#include "wlibc.h"

/**
 * @brief A queue for sbuf_t pointers.
 *
 * This queue is designed to store sbuf_t pointers, providing a mechanism
 * for managing and accessing these buffers in a FIFO (First-In-First-Out) manner.
 * Separate entries and their chunk boundaries are preserved. Original allocation
 * identity is not guaranteed for ordinary buffers: Debug insertion may replace
 * the input allocation; insertion returns the exact retained buffer.
 * Splice wrappers retain their allocation and exclusively owned private pipes
 * in every build. Claimed body bytes must already be in the private pipe;
 * empty bodies need no initialized pipe. Splice entries must not carry lifetime
 * metadata. Mixed ordinary/splice entries preserve FIFO order.
 * While queued, neither payload nor length may be changed through a retained alias;
 * pop first before consuming or modifying an entry.
 */

typedef struct buffer_queue_s buffer_queue_t;

#define i_type ww_sbuffer_queue_t
#define i_key  sbuf_t *
#include "stc/deque.h"

/**
 * @brief Structure representing a buffer queue.
 */
struct buffer_queue_s
{
    buffer_budget_t   *budget;       // Borrowed, stable owner-worker budget; NULL is unbound.
    ww_sbuffer_queue_t q;            // The internal queue data structure (internal)
    size_t             total_len;    // Sum of queued logical payload lengths.
    size_t             total_charge; // Sum of sbufGetQueueCharge() for queued entries.
};

/**
 * @brief Initializes a valid empty queue without reserving storage.
 *
 * This is for protocol state that must always contain a destroyable queue
 * object but does not necessarily use queue storage. The first transactional
 * insertion will reserve its own slot.
 *
 * @param self Queue to initialize. Any previous contents are ignored, not freed.
 */
void bufferqueueInitEmpty(buffer_queue_t *self);

/**
 * @brief Creates a new buffer queue.
 *
 * The returned queue is always in a valid, destroyable state. The requested
 * capacity is best effort: when the eager reservation fails the queue is simply
 * empty and will try again on first insertion. Callers that need the capacity to
 * exist must use bufferqueueInit() instead.
 *
 * @param init_capacity The initial capacity for the queue. If less than 1, a default value is used.
 * @return A newly created buffer queue.
 */
buffer_queue_t bufferqueueCreate(int init_capacity);

/**
 * @brief Initializes a buffer queue and reports whether the eager reservation succeeded.
 *
 * On failure @p self is still a valid empty queue that bufferqueueDestroy() must
 * be called on; only the requested capacity is absent.
 *
 * @param self Queue to initialize. Any previous contents are ignored, not freed.
 * @param init_capacity The initial capacity. If less than 1, a default value is used.
 * @return true when the queue can hold @p init_capacity entries without allocating again.
 */
bool bufferqueueInit(buffer_queue_t *self, int init_capacity);

/**
 * @brief Reserves room for @p extra more entries without inserting anything.
 *
 * This is what makes an insertion transactional: reserve first, and the matching
 * push cannot fail for storage afterwards. Byte and charge totals must still be
 * representable and the attached budget must admit the entry. This reserves only
 * deque storage, never budget allowance.
 *
 * @param self A pointer to the buffer queue.
 * @param extra Number of additional entries the queue must be able to hold.
 * @return false when the reservation could not be satisfied; the queue is unchanged.
 */
bool bufferqueueReserveExtra(buffer_queue_t *self, size_t extra);

/**
 * @brief Transactionally pushes an sbuf_t onto the back of the queue.
 *
 * Either the queue takes ownership and `*b` is updated to the exact retained
 * buffer, or nothing at all happened: entries, byte/charge totals, `*b` and the
 * buffer's lifetime are untouched and the caller still owns the buffer.
 * Unrepresentable byte/charge totals are refused before ownership transfers.
 *
 * Ordering matters here. Debug builds replace ordinary allocations to expose stale
 * aliases, which destroys the caller's original; that replacement must therefore
 * happen only once the insertion is known to succeed. Splice wrappers are retained
 * directly without copying or consuming their private bodies.
 *
 * @param self A pointer to the buffer queue.
 * @param b In/out pointer to the buffer; updated only on success.
 * @return true when the queue took ownership.
 */
bool bufferqueueTryPushBack(buffer_queue_t *self, sbuf_t **b);

/**
 * @brief Transactionally pushes an sbuf_t onto the front of the queue.
 *
 * @see bufferqueueTryPushBack for the exact ownership contract.
 */
bool bufferqueueTryPushFront(buffer_queue_t *self, sbuf_t **b);

/**
 * @brief Destroys a buffer queue and releases its resources.
 *
 * This function reuses all buffers in the queue before freeing the queue itself.
 * It discards queued splice payloads by draining their private pipes, closing a
 * pair on drain failure. Healthy empty pipes survive pool reuse. Nonempty queues
 * must be destroyed on their owning event worker; empty queues need no worker.
 * Releases only this queue's budget contribution. Leaves a valid empty, unbound
 * queue with zero byte and charge totals.
 *
 * @param self A pointer to the buffer queue to be destroyed.
 */
void bufferqueueDestroy(buffer_queue_t *self);

/**
 * @brief Pushes an sbuf_t pointer onto the back of the queue.
 *
 * Fail-fast wrapper over bufferqueueTryPushBack() for callers that have no
 * per-flow recovery path. Refused storage or accounting terminates the process rather
 * than reporting a transfer that did not happen; a node that can reset one flow
 * instead should call the try form directly.
 *
 * @param self A pointer to the buffer queue.
 * @param b A pointer to the sbuf_t to be added to the queue.
 * @return The exact buffer retained by the queue. Debug builds replace ordinary
 *         input allocations to expose stale aliases; splice wrappers stay intact.
 */
sbuf_t *bufferqueuePushBack(buffer_queue_t *self, sbuf_t *b);

/**
 * @brief Pushes an sbuf_t pointer onto the front of the queue.
 *
 * Fail-fast wrapper over bufferqueueTryPushFront(); see bufferqueuePushBack().
 *
 * @param self A pointer to the buffer queue.
 * @param b A pointer to the sbuf_t to be added to the front of the queue.
 * @return The exact buffer retained by the queue. Debug builds replace ordinary
 *         input allocations to expose stale aliases; splice wrappers stay intact.
 */
sbuf_t *bufferqueuePushFront(buffer_queue_t *self, sbuf_t *b);

/**
 * @brief Pops an sbuf_t pointer and releases its attached budget cost.
 *
 * @param self A pointer to the buffer queue.
 * @return A pointer to the sbuf_t at the front of the queue, or NULL if the queue is empty.
 */
sbuf_t *bufferqueuePopFront(buffer_queue_t *self);

/**
 * @brief Gets the sbuf_t pointer at the front of the queue without removing it.
 *
 * @param self A pointer to the buffer queue.
 * @return A pointer to the sbuf_t at the front of the queue, or NULL if the queue is empty.
 */
const sbuf_t *bufferqueueFront(buffer_queue_t *self);

/**
 * @brief Gets the number of elements in the queue.
 *
 * @param self A pointer to the buffer queue.
 * @return The number of sbuf_t pointers currently in the queue.
 */
size_t bufferqueueGetBufCount(buffer_queue_t *self);

/**
 * @brief Gets the total length of the sbuf_t pointers in the queue.
 *
 * @param self A pointer to the buffer queue.
 * @return The total length of the sbuf_t pointers currently in the queue.
 */
size_t bufferqueueGetBufLen(buffer_queue_t *self);

/** O(1) sum of sbufGetQueueCharge() for the entries still owned by this queue.
 * Counts capacity, padding and sbuf overhead independently of logical length;
 * empty entries still contribute. This is the queue-capacity policy, not RSS or
 * kernel pipe memory. Popped/active buffers and cross-queue budgets belong to
 * their owners. Attached budgets enforce admission; callers choose limits and flow-control policy. */
size_t bufferqueueGetCharge(const buffer_queue_t *self);

/** Requires an unbound queue and a live budget. Atomically admits all existing
 * entries; refusal leaves both objects unchanged. Empty attachment cannot fail. */
bool bufferqueueTryAttachBudget(buffer_queue_t *self, buffer_budget_t *budget);
/** Requires a bound queue and an empty reservation. Moves accounting to the
 * active owner without releasing usage or allocating; empty pop stays empty. */
sbuf_t *bufferqueuePopFrontReserved(buffer_queue_t *self, buffer_budget_reservation_t *reservation);
/** Requires the same budget and reservation cost matching the actual buffer.
 * Reserve destination storage before transferring; failure preserves both owners.
 * Reconcile any consumption before calling. Success clears the reservation. */
bool bufferqueueTryPushBackReserved(buffer_queue_t *self, sbuf_t **buf, buffer_budget_reservation_t *reservation);
bool bufferqueueTryPushFrontReserved(buffer_queue_t *self, sbuf_t **buf, buffer_budget_reservation_t *reservation);
/** Move whole queues by assignment, then InitEmpty the relinquished source.
 * The destination must own no storage; destroy an empty destination first.
 * The budget pointer and cached totals travel together, without re-admission. */
