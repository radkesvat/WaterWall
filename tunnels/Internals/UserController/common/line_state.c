#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerSetPayloadModeResolver(tunnel_t *controller, tunnel_t *owner,
                                          usercontroller_payload_mode_resolver_t resolver)
{
    usercontroller_tstate_t *ts = tunnelGetState(controller);
    assert(owner != NULL && resolver != NULL && ! ts->prepared && ts->payload_mode_resolver == NULL);
    ts->payload_mode_owner    = owner;
    ts->payload_mode_resolver = resolver;
}

bool usercontrollerResolvePayloadMode(tunnel_t *t, line_t *l, usercontroller_payload_mode_t *mode)
{
    usercontroller_tstate_t *ts = tunnelGetState(t);
    if (ts->payload_mode_from_destination)
    {
        switch (addresscontextClassifyTransport(lineGetDestinationAddressContext(l)))
        {
        case kAddressContextTransportTcp:
            *mode = kUserControllerPayloadStream;
            return true;
        case kAddressContextTransportUdp:
            *mode = kUserControllerPayloadDatagram;
            return true;
        case kAddressContextTransportNone:
        case kAddressContextTransportUnsupported:
            LOGW("UserController: rejected line: payload-mode dest_context->protocol requires exactly TCP or UDP "
                 "at Init");
            return false;
        }
    }
    *mode = ts->payload_mode_resolver != NULL ? ts->payload_mode_resolver(ts->payload_mode_owner, l)
                                              : ts->fixed_payload_mode;
    if (*mode != kUserControllerPayloadStream && *mode != kUserControllerPayloadDatagram)
    {
        LOGF("UserController: creator returned an invalid payload mode");
        abortProgramNow(1);
    }
    return true;
}

void usercontrollerOpenLine(tunnel_t *tunnel, line_t *line, bool from_next)
{
    usercontroller_payload_mode_t mode;
    if (! usercontrollerResolvePayloadMode(tunnel, line, &mode))
    {
        if (from_next)
            tunnelNextUpStreamFinish(tunnel, line);
        else
            tunnelPrevDownStreamFinish(tunnel, line);
        return;
    }

    usercontroller_lstate_t *state = usercontrollerGetLineState(tunnel, line);
    state->phase                   = kUserControllerOpen;
    state->started_from_next       = from_next;
    state->handle                  = userHandleEmpty();
    state->payload_mode            = mode;
    usercontrollerBandwidthInitialize(tunnel, line);
    user_admission_result_t result = usercontrollerTunnelTryManageLine(tunnel, line);
    if (result != kUserAdmissionOk)
    {
        usercontrollerLogAdmissionRejected(tunnel, line, state, result);
        usercontrollerLinestateDestroy(tunnel, line);
        if (from_next)
            tunnelNextUpStreamFinish(tunnel, line);
        else
            tunnelPrevDownStreamFinish(tunnel, line);
        return;
    }

    if (from_next)
        tunnelPrevDownStreamInit(tunnel, line);
    else
        tunnelNextUpStreamInit(tunnel, line);
}
