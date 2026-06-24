#include "structure.h"

#include "DomainResolver/interface.h"

api_result_t domainresolverTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), message);
    return (api_result_t) {.result_code = kApiResultOk};
}

void domainresolverTunnelUseLineStrategy(tunnel_t *t, bool enabled)
{
    domainresolver_tstate_t *ts = tunnelGetState(t);
    ts->use_line_strategy       = enabled;
}

void domainresolverTunnelAllowMissingDestination(tunnel_t *t, bool enabled)
{
    domainresolver_tstate_t *ts = tunnelGetState(t);
    ts->allow_missing_destination = enabled;
}
