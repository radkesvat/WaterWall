#include "structure.h"

#include "loggers/network_logger.h"

static tunnel_t *ipmanipulatorUnchainedTlsChild(tunnel_t *t)
{
    ipmanipulator_tstate_t *ts    = tunnelGetState(t);
    tunnel_t               *child = ts->internal_tls_client_tunnel;
    return child != NULL && tunnelGetChain(child) == NULL ? child : NULL;
}

void ipmanipulatorOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard   context;
    tunnel_t *child = ipmanipulatorUnchainedTlsChild(t);
    if (child != NULL)
    {
        tunnelOwnedChildQuiesceRequest(child);
    }
}

void ipmanipulatorOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard   context;
    tunnel_t *child = ipmanipulatorUnchainedTlsChild(t);
    if (child != NULL)
    {
        tunnelOwnedChildWorkerQuiesce(child, wid);
    }
}

void ipmanipulatorOnQuiesceWait(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard   context;
    tunnel_t *child = ipmanipulatorUnchainedTlsChild(t);
    if (child != NULL)
    {
        tunnelOwnedChildQuiesceWait(child);
    }
}

void ipmanipulatorOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard   context;
    tunnel_t *child = ipmanipulatorUnchainedTlsChild(t);
    if (child != NULL)
    {
        tunnelOwnedChildWorkerStop(child, wid);
    }
}

void ipmanipulatorOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard   context;
    tunnel_t *child = ipmanipulatorUnchainedTlsChild(t);
    if (child != NULL)
    {
        tunnelOwnedChildStop(child);
    }
}
