#pragma once

/*
 * One tunnel reference that an asynchronous callback may safely observe.
 *
 * A bridge node hands its tunnel pointer to callbacks it does not own the
 * scheduling of - lwIP core-thread callbacks, worker messages, timers. Those may
 * still be queued, or already running, when the node is being stopped, so they
 * cannot dereference the tunnel directly.
 *
 * The session solves that with two independent pieces:
 *
 *   - a lifetime gate, which admits callbacks until pre-stop closes it and then
 *     waits for the ones already inside to leave; and
 *   - a reference count on the allocation itself, so a callback that is holding
 *     the session survives the node's destruction and frees it on its way out.
 *
 * Ordering: a successful Enter owns exactly one gate entry and one guaranteed
 * tunnel observation; Detach prevents any new observation; the allocation dies
 * only after the final Unref.
 *
 * ConnectionToPackets and PacketsToConnection each carried a private copy of
 * this, identical after prefix substitution. It is deliberately just these
 * primitives - each bridge keeps its own neighbour gates, packet gates, worker
 * messages and stop sequence explicit, because those are not the same between
 * the two directions.
 */

#include "tunnel.h"

#include "devices/device_lifetime.h"

typedef struct tunnel_async_session_s
{
    atomic_uint            refcount;
    atomic_uintptr_t       tunnel;
    device_lifetime_gate_t callback_gate;
    /* Static node name, used only to identify the owner in a fatal diagnostic. */
    const char *owner_name;
} tunnel_async_session_t;

/**
 * @brief Create a session holding @p t, with one reference and a closed gate.
 *
 * The gate starts closed; the owner opens it in its start hook, once every
 * resource a callback could observe is published.
 *
 * @param t Tunnel the session publishes to callbacks.
 * @param owner_name Node name used in the fatal diagnostic for a refcount fault.
 * @return tunnel_async_session_t* Session, or NULL when the allocation failed.
 */
tunnel_async_session_t *tunnelasyncsessionCreate(tunnel_t *t, const char *owner_name);

/** @brief Take one more reference. Fatal on overflow or resurrection from zero. */
void tunnelasyncsessionRef(tunnel_async_session_t *session);

/** @brief Drop one reference, freeing the session when it was the last. */
void tunnelasyncsessionUnref(tunnel_async_session_t *session);

/**
 * @brief Try to enter the callback gate and observe the tunnel.
 *
 * @param session Session to enter.
 * @param out_tunnel Receives the observed tunnel on success; untouched on failure.
 * @return true when the caller is inside the gate and must pair this with
 *         tunnelasyncsessionLeave(). false when the gate is closed or the
 *         tunnel has been detached, in which case nothing was acquired.
 */
bool tunnelasyncsessionEnter(tunnel_async_session_t *session, tunnel_t **out_tunnel);

/** @brief Leave the callback gate after a successful Enter. */
void tunnelasyncsessionLeave(tunnel_async_session_t *session);

/**
 * @brief Open the gate so callbacks may enter. Call once, from the start hook.
 *
 * @return false when the gate was not closed, which means the owner published
 *         it twice.
 */
bool tunnelasyncsessionOpen(tunnel_async_session_t *session);

/**
 * @brief Close the gate and wait for every callback already inside to leave.
 *
 * Must not be called from inside the gate. After it returns, no callback is
 * observing the tunnel and none can start.
 */
void tunnelasyncsessionCloseAndQuiesce(tunnel_async_session_t *session);

/**
 * @brief Advisory check used by a callback that already owns a gate entry.
 *
 * A false result means close has started and the callback must not publish new
 * asynchronous work. A true result grants no entry or lifetime ownership.
 */
bool tunnelasyncsessionIsAccepting(const tunnel_async_session_t *session);

/**
 * @brief Stop publishing the tunnel.
 *
 * A callback that already entered keeps the pointer it observed; a later Enter
 * fails. This does not free the session - the last Unref does.
 */
void tunnelasyncsessionDetach(tunnel_async_session_t *session);
