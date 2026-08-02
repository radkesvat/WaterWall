#include "structure.h"

#include "loggers/network_logger.h"

/*
 * Tunnel APIs run on an event worker and take ownership of `message`.
 *
 * tunnelapiRecycleMessage() returns the buffer to the calling worker's pool and
 * reports kApiResultOk; it destroys the buffer and reports kApiResultError when
 * the caller is not an ordinary event worker, so an unregistered or lwIP thread
 * can never borrow worker 0's pool. Use tunnelapiUnsupportedMessage() instead
 * when the node deliberately exposes no API.
 *
 * If this node grows a real API, keep the same ownership rule: consume `message`
 * on every path, and take working buffers from the *caller's* worker pool
 * (getCurrentEventWorkerBufferPool()), never from getWorkerBufferPool(0).
 */
api_result_t templateTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    (void) instance;
    // Implement the API here
    return tunnelapiRecycleMessage(message);
}
